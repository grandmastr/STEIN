use std::collections::HashMap;
use std::fmt;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use stein_core::PresenceState;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{
    Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCapturePicker, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{IDXGIAdapter, IDXGIDevice};
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::{
    RO_INIT_MULTITHREADED, RO_INIT_SINGLETHREADED, RoInitialize, RoUninitialize,
};
use windows::Win32::UI::Shell::IInitializeWithWindow;
use windows::core::Interface;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
    TranslateMessage, WM_QUIT, WS_EX_TOOLWINDOW, WS_OVERLAPPED,
};
use zeroize::Zeroize;

pub(crate) const PIXEL_BINDING_PREFIX: &str = "winpixel:v1:";
pub(crate) const MAXIMUM_PIXEL_WIDTH: u32 = 1_920;
pub(crate) const MAXIMUM_PIXEL_HEIGHT: u32 = 1_080;
pub(crate) const MAXIMUM_TRANSIENT_PIXEL_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const PIXEL_CAPTURE_DEADLINE: Duration = Duration::from_secs(2);
const NATIVE_SELECTION_CAPACITY: usize = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const SUPPORT_PROBE_DEADLINE: Duration = Duration::from_secs(2);
const EMPTY_INTERFACE: i32 = 0x8000_4003_u32 as i32;
const MAXIMUM_DISPOSABLE_CAPTURE_WORKERS: usize = 4;
static ACTIVE_CAPTURE_WORKERS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PixelErrorKind {
    Cancelled,
    BoundaryLost,
    ProtectedSurface,
    Unavailable,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PixelError {
    pub(crate) kind: PixelErrorKind,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct WindowsPixelBinding(Uuid);

impl WindowsPixelBinding {
    pub(crate) fn parse(value: &str) -> Result<Self, PixelError> {
        let suffix = value
            .strip_prefix(PIXEL_BINDING_PREFIX)
            .ok_or_else(boundary_lost)?;
        let id = Uuid::parse_str(suffix).map_err(|_| boundary_lost())?;
        let binding = Self(id);
        if binding.to_string() != value {
            return Err(boundary_lost());
        }
        Ok(binding)
    }

    fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for WindowsPixelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{PIXEL_BINDING_PREFIX}{}", self.0)
    }
}

impl fmt::Debug for WindowsPixelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPixelBinding")
            .finish_non_exhaustive()
    }
}

pub(crate) struct PixelFrameSummary {
    pub(crate) bounded_text: String,
}

impl fmt::Debug for PixelFrameSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PixelFrameSummary")
            .field("bytes", &self.bounded_text.len())
            .finish_non_exhaustive()
    }
}

pub(crate) trait PixelCaptureSource: Send + Sync {
    fn is_revoked(&self) -> bool;

    fn boundary_is_open(&self) -> bool;

    fn capture_one(
        &self,
        deadline: Instant,
        external_cancellation: &CancellationToken,
        stop_cancellation: &CancellationToken,
    ) -> Result<PixelFrameSummary, PixelError>;
}

pub(crate) trait PixelCaptureFactory: Send + Sync {
    fn is_available(&self) -> bool;

    fn select(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<WindowsPixelBinding>, PixelError>;

    fn release(&self, binding: &WindowsPixelBinding) -> Result<(), PixelError>;

    fn open(
        &self,
        binding: &WindowsPixelBinding,
    ) -> Result<Arc<dyn PixelCaptureSource>, PixelError>;
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailablePixelCaptureFactory;

#[cfg(test)]
impl PixelCaptureFactory for UnavailablePixelCaptureFactory {
    fn is_available(&self) -> bool {
        false
    }

    fn select(
        &self,
        _cancellation: &CancellationToken,
    ) -> Result<Option<WindowsPixelBinding>, PixelError> {
        Err(unavailable())
    }

    fn release(&self, _binding: &WindowsPixelBinding) -> Result<(), PixelError> {
        Ok(())
    }

    fn open(
        &self,
        _binding: &WindowsPixelBinding,
    ) -> Result<Arc<dyn PixelCaptureSource>, PixelError> {
        Err(unavailable())
    }
}

struct NativeSelection {
    item: GraphicsCaptureItem,
    revoked: Arc<AtomicBool>,
    closed_token: i64,
}

impl Drop for NativeSelection {
    fn drop(&mut self) {
        self.revoked.store(true, Ordering::Release);
        let _ = self.item.RemoveClosed(self.closed_token);
    }
}

struct NativePixelCaptureSource {
    selection: Arc<NativeSelection>,
}

impl PixelCaptureSource for NativePixelCaptureSource {
    fn is_revoked(&self) -> bool {
        self.selection.revoked.load(Ordering::Acquire)
    }

    fn boundary_is_open(&self) -> bool {
        !self.is_revoked() && crate::presence::current_native_presence() == PresenceState::Active
    }

    fn capture_one(
        &self,
        deadline: Instant,
        external_cancellation: &CancellationToken,
        stop_cancellation: &CancellationToken,
    ) -> Result<PixelFrameSummary, PixelError> {
        bounded_native_capture(
            Arc::clone(&self.selection),
            deadline,
            external_cancellation,
            stop_cancellation,
        )
    }
}

/// Picker-owned Windows Graphics Capture selections. A `GraphicsCaptureItem`
/// has no documented serializable identity, so bindings are process-local
/// opaque tokens. After daemon restart `open` fails closed and the user must
/// explicitly select again; the adapter never recreates a broader HWND or
/// display capture programmatically.
pub(crate) struct NativePixelCaptureFactory {
    selections: Mutex<HashMap<WindowsPixelBinding, Arc<NativeSelection>>>,
    supported: bool,
}

impl NativePixelCaptureFactory {
    pub(crate) fn new() -> Self {
        Self {
            selections: Mutex::new(HashMap::new()),
            supported: probe_graphics_capture_support(),
        }
    }
}

impl fmt::Debug for NativePixelCaptureFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePixelCaptureFactory")
            .field("supported", &self.supported)
            .finish_non_exhaustive()
    }
}

impl PixelCaptureFactory for NativePixelCaptureFactory {
    fn is_available(&self) -> bool {
        self.supported
    }

    fn select(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<WindowsPixelBinding>, PixelError> {
        if !self.supported {
            return Err(unavailable());
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let item = match pick_graphics_capture_item(cancellation)? {
            Some(item) => item,
            None => return Ok(None),
        };
        if cancellation.is_cancelled() {
            drop(item);
            return Ok(None);
        }
        validate_dimensions(item.Size().map_err(|_| unavailable())?)?;

        let revoked = Arc::new(AtomicBool::new(false));
        let closed_revoked = Arc::clone(&revoked);
        let closed_token = item
            .Closed(&TypedEventHandler::new(move |_, _| {
                closed_revoked.store(true, Ordering::Release);
                Ok(())
            }))
            .map_err(|_| unavailable())?;
        let selection = Arc::new(NativeSelection {
            item,
            revoked,
            closed_token,
        });
        let mut selections = self.selections.lock().map_err(|_| internal())?;
        if selections.len() >= NATIVE_SELECTION_CAPACITY {
            return Err(unavailable());
        }
        let mut binding = WindowsPixelBinding::new();
        while selections.contains_key(&binding) {
            binding = WindowsPixelBinding::new();
        }
        selections.insert(binding, selection);
        Ok(Some(binding))
    }

    fn release(&self, binding: &WindowsPixelBinding) -> Result<(), PixelError> {
        let selection = self
            .selections
            .lock()
            .map_err(|_| internal())?
            .remove(binding);
        if let Some(selection) = &selection {
            selection.revoked.store(true, Ordering::Release);
        }
        drop(selection);
        // A canonical token missing after restart is already released. This is
        // intentionally idempotent but never makes the token reusable.
        Ok(())
    }

    fn open(
        &self,
        binding: &WindowsPixelBinding,
    ) -> Result<Arc<dyn PixelCaptureSource>, PixelError> {
        let selection = self
            .selections
            .lock()
            .map_err(|_| internal())?
            .get(binding)
            .cloned()
            .ok_or_else(boundary_lost)?;
        if selection.revoked.load(Ordering::Acquire) {
            return Err(boundary_lost());
        }
        Ok(Arc::new(NativePixelCaptureSource { selection }))
    }
}

fn probe_graphics_capture_support() -> bool {
    let (sender, receiver) = mpsc::sync_channel(1);
    if thread::Builder::new()
        .name("stein-pixel-support-probe".to_owned())
        .spawn(move || {
            let supported = ComApartment::sta().is_ok_and(|_apartment| {
                GraphicsCaptureSession::IsSupported().unwrap_or(false)
                    && GraphicsCapturePicker::new().is_ok()
            });
            let _ = sender.send(supported);
        })
        .is_err()
    {
        return false;
    }
    receiver
        .recv_timeout(SUPPORT_PROBE_DEADLINE)
        .unwrap_or(false)
}

fn bounded_native_capture(
    selection: Arc<NativeSelection>,
    deadline: Instant,
    external_cancellation: &CancellationToken,
    stop_cancellation: &CancellationToken,
) -> Result<PixelFrameSummary, PixelError> {
    let lease = CaptureWorkerLease::try_acquire()?;
    let operation_cancellation = CancellationToken::new();
    let worker_cancellation = operation_cancellation.clone();
    let item = selection.item.clone();
    let revoked = Arc::clone(&selection.revoked);
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("stein-pixel-one-frame-worker".to_owned())
        .spawn(move || {
            let _lease = lease;
            let result = capture_native_frame(
                &item,
                &revoked,
                deadline,
                &worker_cancellation,
                &CancellationToken::new(),
            );
            let _ = sender.send(result);
        })
        .map_err(|_| internal())?;

    loop {
        if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
            operation_cancellation.cancel();
            return Err(cancelled());
        }
        if selection.revoked.load(Ordering::Acquire) {
            operation_cancellation.cancel();
            return Err(boundary_lost());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            operation_cancellation.cancel();
            return Err(unavailable());
        }
        match receiver.recv_timeout(remaining.min(POLL_INTERVAL)) {
            Ok(result) => {
                let join_failed = worker.join().is_err();
                if join_failed {
                    return Err(internal());
                }
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                return Err(internal());
            }
        }
    }
}

#[derive(Debug)]
struct CaptureWorkerLease;

impl CaptureWorkerLease {
    fn try_acquire() -> Result<Self, PixelError> {
        ACTIVE_CAPTURE_WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAXIMUM_DISPOSABLE_CAPTURE_WORKERS).then_some(active + 1)
            })
            .map_err(|_| unavailable())?;
        Ok(Self)
    }
}

impl Drop for CaptureWorkerLease {
    fn drop(&mut self) {
        ACTIVE_CAPTURE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn pick_graphics_capture_item(
    cancellation: &CancellationToken,
) -> Result<Option<GraphicsCaptureItem>, PixelError> {
    let _apartment = ComApartment::sta()?;
    if crate::presence::current_native_presence() != PresenceState::Active {
        return Err(protected_surface());
    }
    let owner = PickerOwnerWindow::new()?;
    let picker = GraphicsCapturePicker::new().map_err(|_| unavailable())?;
    let initialize: IInitializeWithWindow = picker.cast().map_err(|_| unavailable())?;
    // SAFETY: `owner` is a live top-level HWND on this thread for the entire
    // picker operation. No HWND or title crosses the platform boundary.
    unsafe { initialize.Initialize(HWND(owner.raw.cast())) }.map_err(|_| unavailable())?;
    let operation = picker.PickSingleItemAsync().map_err(|_| unavailable())?;
    loop {
        let status = operation.Status().map_err(|_| unavailable())?;
        match status.0 {
            0 => {
                if cancellation.is_cancelled()
                    || crate::presence::current_native_presence() != PresenceState::Active
                {
                    let _ = operation.Cancel();
                    return Ok(None);
                }
                pump_picker_messages()?;
                thread::sleep(POLL_INTERVAL);
            }
            1 => {
                return operation.GetResults().map(Some).or_else(|error| {
                    if error.code().0 == EMPTY_INTERFACE {
                        Ok(None)
                    } else {
                        Err(unavailable())
                    }
                });
            }
            2 => return Ok(None),
            _ => return Err(unavailable()),
        }
    }
}

fn pump_picker_messages() -> Result<(), PixelError> {
    loop {
        // SAFETY: zero is a valid initial state for MSG, and PeekMessageW
        // initializes it before the dispatch path reads any field.
        let mut message = unsafe { std::mem::zeroed::<MSG>() };
        // SAFETY: `message` is writable and this drains only messages owned by
        // the current picker STA. The HWND filter is deliberately null so COM
        // and system-picker thread messages are serviced too.
        if unsafe { PeekMessageW(&mut message, ptr::null_mut(), 0, 0, PM_REMOVE) } == 0 {
            return Ok(());
        }
        if message.message == WM_QUIT {
            return Err(unavailable());
        }
        // SAFETY: PeekMessageW returned one initialized message for this
        // thread; translation and dispatch preserve normal Win32 ownership.
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

struct ComApartment;

impl ComApartment {
    fn mta() -> Result<Self, PixelError> {
        // SAFETY: balances the successful initialization in Drop on this same
        // short-lived worker thread.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|_| unavailable())?;
        Ok(Self)
    }

    fn sta() -> Result<Self, PixelError> {
        // SAFETY: balances the successful initialization in Drop on this same
        // picker thread.
        unsafe { RoInitialize(RO_INIT_SINGLETHREADED) }.map_err(|_| unavailable())?;
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after a successful RoInitialize on the
        // current thread and is not movable across the native call boundary.
        unsafe { RoUninitialize() };
    }
}

struct PickerOwnerWindow {
    raw: windows_sys::Win32::Foundation::HWND,
}

impl PickerOwnerWindow {
    fn new() -> Result<Self, PixelError> {
        const STATIC_CLASS: &[u16] = &[
            b'S' as u16,
            b'T' as u16,
            b'A' as u16,
            b'T' as u16,
            b'I' as u16,
            b'C' as u16,
            0,
        ];
        const SAFE_TITLE: &[u16] = &[
            b'S' as u16,
            b'T' as u16,
            b'E' as u16,
            b'I' as u16,
            b'N' as u16,
            b' ' as u16,
            b's' as u16,
            b'c' as u16,
            b'r' as u16,
            b'e' as u16,
            b'e' as u16,
            b'n' as u16,
            b' ' as u16,
            b's' as u16,
            b'e' as u16,
            b'l' as u16,
            b'e' as u16,
            b'c' as u16,
            b't' as u16,
            b'i' as u16,
            b'o' as u16,
            b'n' as u16,
            0,
        ];
        // SAFETY: both UTF-16 strings are static and terminated. The system
        // STATIC class needs no application registration. The hidden 1x1
        // top-level window exists solely to owner-bind the trusted OS picker.
        let raw = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                STATIC_CLASS.as_ptr(),
                SAFE_TITLE.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                1,
                1,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if raw.is_null() {
            return Err(unavailable());
        }
        Ok(Self { raw })
    }
}

impl Drop for PickerOwnerWindow {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: the HWND is live and destroyed on its creating thread.
            unsafe { DestroyWindow(self.raw) };
        }
    }
}

fn capture_native_frame(
    item: &GraphicsCaptureItem,
    revoked: &AtomicBool,
    deadline: Instant,
    external_cancellation: &CancellationToken,
    stop_cancellation: &CancellationToken,
) -> Result<PixelFrameSummary, PixelError> {
    let _apartment = ComApartment::mta()?;
    check_capture_boundary(revoked, deadline, external_cancellation, stop_cancellation)?;
    let initial_size = item.Size().map_err(|_| boundary_lost())?;
    validate_dimensions(initial_size)?;

    let (d3d_device, d3d_context, winrt_device) = create_direct3d_device()?;
    let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &winrt_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        1,
        initial_size,
    )
    .map_err(|_| unavailable())?;
    let session = frame_pool
        .CreateCaptureSession(item)
        .map_err(|_| protected_surface())?;
    // Cursor pixels are unrelated user input and are not part of the selected
    // visual source. The capture border is deliberately left at its secure OS
    // default; STEIN never requests borderless/programmatic capabilities.
    session
        .SetIsCursorCaptureEnabled(false)
        .map_err(|_| unavailable())?;
    let (arrived_sender, arrived_receiver) = mpsc::sync_channel(1);
    let arrived_token = frame_pool
        .FrameArrived(&TypedEventHandler::new(move |_, _| {
            let _ = arrived_sender.try_send(());
            Ok(())
        }))
        .map_err(|_| unavailable())?;
    let guard = CaptureSessionGuard {
        session,
        frame_pool,
        arrived_token,
    };
    guard.session.StartCapture().map_err(|_| unavailable())?;

    loop {
        check_capture_boundary(revoked, deadline, external_cancellation, stop_cancellation)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match arrived_receiver.recv_timeout(remaining.min(POLL_INTERVAL)) {
            Ok(()) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(unavailable()),
        }
    }

    check_capture_boundary(revoked, deadline, external_cancellation, stop_cancellation)?;
    let frame = guard
        .frame_pool
        .TryGetNextFrame()
        .map_err(|_| unavailable())?;
    let content_size = frame.ContentSize().map_err(|_| unavailable())?;
    validate_dimensions(content_size)?;
    let surface = frame.Surface().map_err(|_| unavailable())?;
    let access: IDirect3DDxgiInterfaceAccess = surface.cast().map_err(|_| unavailable())?;
    // SAFETY: the WinRT surface exposes this documented interop interface and
    // requests the exact D3D11 texture interface IID.
    let source_texture: ID3D11Texture2D =
        unsafe { access.GetInterface() }.map_err(|_| unavailable())?;
    let mut transient = copy_texture_to_transient(
        &d3d_device,
        &d3d_context,
        &source_texture,
        content_size.Width as u32,
        content_size.Height as u32,
    )?;
    frame.Close().map_err(|_| unavailable())?;
    drop(surface);
    drop(source_texture);
    drop(frame);
    drop(guard);

    check_capture_boundary(revoked, deadline, external_cancellation, stop_cancellation)?;
    let summary = summarize_transient_frame(&transient)?;
    transient.clear();
    check_capture_boundary(revoked, deadline, external_cancellation, stop_cancellation)?;
    Ok(summary)
}

struct CaptureSessionGuard {
    session: windows::Graphics::Capture::GraphicsCaptureSession,
    frame_pool: Direct3D11CaptureFramePool,
    arrived_token: i64,
}

impl Drop for CaptureSessionGuard {
    fn drop(&mut self) {
        let _ = self.session.Close();
        let _ = self.frame_pool.RemoveFrameArrived(self.arrived_token);
        let _ = self.frame_pool.Close();
    }
}

fn create_direct3d_device()
-> Result<(ID3D11Device, ID3D11DeviceContext, IDirect3DDevice), PixelError> {
    let mut device = None;
    let mut context = None;
    // SAFETY: all output pointers refer to valid Options and no adapter or
    // software module is supplied. D3D owns the returned COM references.
    unsafe {
        D3D11CreateDevice(
            None::<&IDXGIAdapter>,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    }
    .map_err(|_| unavailable())?;
    let device = device.ok_or_else(unavailable)?;
    let context = context.ok_or_else(unavailable)?;
    let dxgi_device: IDXGIDevice = device.cast().map_err(|_| unavailable())?;
    // SAFETY: `dxgi_device` is the D3D11 device's documented DXGI interface.
    let inspectable =
        unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device) }.map_err(|_| unavailable())?;
    let winrt_device: IDirect3DDevice = inspectable.cast().map_err(|_| unavailable())?;
    Ok((device, context, winrt_device))
}

fn copy_texture_to_transient(
    device: &ID3D11Device,
    context: &ID3D11DeviceContext,
    source: &ID3D11Texture2D,
    content_width: u32,
    content_height: u32,
) -> Result<TransientPixelFrame, PixelError> {
    let mut source_desc = D3D11_TEXTURE2D_DESC::default();
    // SAFETY: `source_desc` is writable and `source` is live.
    unsafe { source.GetDesc(&mut source_desc) };
    if source_desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM
        || source_desc.Width < content_width
        || source_desc.Height < content_height
    {
        return Err(unavailable());
    }
    validate_dimensions(windows::Graphics::SizeInt32 {
        Width: i32::try_from(source_desc.Width).map_err(|_| unavailable())?,
        Height: i32::try_from(source_desc.Height).map_err(|_| unavailable())?,
    })?;
    validate_dimensions(windows::Graphics::SizeInt32 {
        Width: content_width as i32,
        Height: content_height as i32,
    })?;
    let staging_desc = D3D11_TEXTURE2D_DESC {
        Width: source_desc.Width,
        Height: source_desc.Height,
        MipLevels: 1,
        ArraySize: 1,
        Format: source_desc.Format,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };
    let mut staging = None;
    // SAFETY: the descriptor is fully initialized; no initial data is used and
    // the writable Option receives the owned staging texture reference.
    unsafe { device.CreateTexture2D(&staging_desc, None, Some(&mut staging)) }
        .map_err(|_| unavailable())?;
    let staging = staging.ok_or_else(unavailable)?;
    // SAFETY: source and destination have matching D3D11 texture descriptors.
    unsafe { context.CopyResource(&staging, source) };
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    // SAFETY: the staging texture was created for CPU read and `mapped` is a
    // writable descriptor that remains valid until the matching Unmap.
    unsafe { context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) }
        .map_err(|_| unavailable())?;
    let result = copy_mapped_pixels(
        mapped.pData.cast_const().cast(),
        mapped.RowPitch as usize,
        content_width,
        content_height,
    );
    // SAFETY: balances the successful Map above on the same resource/context.
    unsafe { context.Unmap(&staging, 0) };
    result
}

fn copy_mapped_pixels(
    data: *const u8,
    row_pitch: usize,
    width: u32,
    height: u32,
) -> Result<TransientPixelFrame, PixelError> {
    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(unavailable)?;
    let decoded_bytes = row_bytes
        .checked_mul(height as usize)
        .ok_or_else(unavailable)?;
    if data.is_null()
        || row_pitch < row_bytes
        || decoded_bytes == 0
        || decoded_bytes > MAXIMUM_TRANSIENT_PIXEL_BYTES
    {
        return Err(unavailable());
    }
    let mapped_bytes = row_pitch
        .checked_mul(height as usize)
        .ok_or_else(unavailable)?;
    if mapped_bytes > MAXIMUM_TRANSIENT_PIXEL_BYTES {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(decoded_bytes)
        .map_err(|_| unavailable())?;
    for row in 0..height as usize {
        let offset = row.checked_mul(row_pitch).ok_or_else(unavailable)?;
        // SAFETY: D3D's successful Map exposes at least RowPitch * Height live
        // bytes until Unmap; each requested row is within that validated span.
        let source = unsafe { std::slice::from_raw_parts(data.add(offset), row_bytes) };
        bytes.extend_from_slice(source);
    }
    Ok(TransientPixelFrame {
        width,
        height,
        bytes,
    })
}

struct TransientPixelFrame {
    width: u32,
    height: u32,
    bytes: Vec<u8>,
}

impl TransientPixelFrame {
    fn clear(&mut self) {
        self.bytes.zeroize();
        self.bytes.clear();
    }
}

impl Drop for TransientPixelFrame {
    fn drop(&mut self) {
        self.clear();
    }
}

fn summarize_transient_frame(frame: &TransientPixelFrame) -> Result<PixelFrameSummary, PixelError> {
    if frame.bytes.is_empty() || !frame.bytes.len().is_multiple_of(4) {
        return Err(protected_surface());
    }
    let pixel_count = frame.bytes.len() / 4;
    let step = (pixel_count / 4_096).max(1);
    let mut count = 0_u64;
    let mut sum = 0_u64;
    let mut sum_squared = 0_u64;
    let mut minimum = u8::MAX;
    let mut maximum = u8::MIN;
    for pixel in (0..pixel_count).step_by(step) {
        let index = pixel * 4;
        let blue = u32::from(frame.bytes[index]);
        let green = u32::from(frame.bytes[index + 1]);
        let red = u32::from(frame.bytes[index + 2]);
        let luminance = ((54 * red + 183 * green + 19 * blue) >> 8) as u8;
        minimum = minimum.min(luminance);
        maximum = maximum.max(luminance);
        count += 1;
        sum += u64::from(luminance);
        sum_squared += u64::from(luminance) * u64::from(luminance);
    }
    if count == 0 || maximum.saturating_sub(minimum) < 4 {
        // Blank and uniformly protected surfaces are deliberately
        // indistinguishable and both fail closed.
        return Err(protected_surface());
    }
    let mean = sum / count;
    let variance = sum_squared / count - mean.saturating_mul(mean);
    let luminance = match mean {
        0..=63 => "dark",
        64..=191 => "balanced",
        _ => "bright",
    };
    let detail = match variance {
        0..=63 => "low",
        64..=1_023 => "moderate",
        _ => "high",
    };
    Ok(PixelFrameSummary {
        bounded_text: format!(
            "selected visual source {}x{}; luminance={luminance}; detail={detail}",
            frame.width, frame.height
        ),
    })
}

fn validate_dimensions(size: windows::Graphics::SizeInt32) -> Result<(), PixelError> {
    let width = u32::try_from(size.Width).map_err(|_| unavailable())?;
    let height = u32::try_from(size.Height).map_err(|_| unavailable())?;
    let decoded_bytes = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(height as usize))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(unavailable)?;
    if width == 0
        || height == 0
        || width > MAXIMUM_PIXEL_WIDTH
        || height > MAXIMUM_PIXEL_HEIGHT
        || decoded_bytes > MAXIMUM_TRANSIENT_PIXEL_BYTES
    {
        return Err(unavailable());
    }
    Ok(())
}

fn check_capture_boundary(
    revoked: &AtomicBool,
    deadline: Instant,
    external_cancellation: &CancellationToken,
    stop_cancellation: &CancellationToken,
) -> Result<(), PixelError> {
    if external_cancellation.is_cancelled() || stop_cancellation.is_cancelled() {
        return Err(cancelled());
    }
    if revoked.load(Ordering::Acquire) {
        return Err(boundary_lost());
    }
    if Instant::now() >= deadline {
        return Err(unavailable());
    }
    if crate::presence::current_native_presence() != PresenceState::Active {
        return Err(protected_surface());
    }
    Ok(())
}

const fn cancelled() -> PixelError {
    PixelError {
        kind: PixelErrorKind::Cancelled,
    }
}

const fn boundary_lost() -> PixelError {
    PixelError {
        kind: PixelErrorKind::BoundaryLost,
    }
}

const fn protected_surface() -> PixelError {
    PixelError {
        kind: PixelErrorKind::ProtectedSurface,
    }
}

const fn unavailable() -> PixelError {
    PixelError {
        kind: PixelErrorKind::Unavailable,
    }
}

const fn internal() -> PixelError {
    PixelError {
        kind: PixelErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_frame(width: u32, height: u32) -> TransientPixelFrame {
        let mut bytes = Vec::with_capacity(width as usize * height as usize * 4);
        for index in 0..(width * height) {
            let value = (index % 251) as u8;
            bytes.extend_from_slice(&[value, value.wrapping_mul(3), 255 - value, 255]);
        }
        TransientPixelFrame {
            width,
            height,
            bytes,
        }
    }

    #[test]
    fn pixel_binding_is_canonical_content_free_and_bounded() {
        let binding = WindowsPixelBinding::new();
        let encoded = binding.to_string();
        assert!(encoded.starts_with(PIXEL_BINDING_PREFIX));
        assert!(encoded.len() < 64);
        assert_eq!(WindowsPixelBinding::parse(&encoded).unwrap(), binding);
        assert!(!encoded.contains('\\'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('@'));
        assert!(WindowsPixelBinding::parse(&encoded.to_uppercase()).is_err());
        assert!(
            WindowsPixelBinding::parse("winpixel:v2:00000000-0000-0000-0000-000000000000").is_err()
        );
    }

    #[test]
    fn pixel_dimensions_enforce_frame_and_decoded_storage_bounds() {
        assert!(
            validate_dimensions(windows::Graphics::SizeInt32 {
                Width: 1,
                Height: 1
            })
            .is_ok()
        );
        assert!(
            validate_dimensions(windows::Graphics::SizeInt32 {
                Width: MAXIMUM_PIXEL_WIDTH as i32,
                Height: MAXIMUM_PIXEL_HEIGHT as i32,
            })
            .is_ok()
        );
        for size in [
            windows::Graphics::SizeInt32 {
                Width: 0,
                Height: 1,
            },
            windows::Graphics::SizeInt32 {
                Width: 1,
                Height: 0,
            },
            windows::Graphics::SizeInt32 {
                Width: -1,
                Height: 1,
            },
            windows::Graphics::SizeInt32 {
                Width: (MAXIMUM_PIXEL_WIDTH + 1) as i32,
                Height: 1,
            },
            windows::Graphics::SizeInt32 {
                Width: 1,
                Height: (MAXIMUM_PIXEL_HEIGHT + 1) as i32,
            },
        ] {
            assert_eq!(
                validate_dimensions(size).unwrap_err().kind,
                PixelErrorKind::Unavailable
            );
        }
    }

    #[test]
    fn normalization_emits_only_coarse_non_image_metadata() {
        let frame = synthetic_frame(64, 32);
        let summary = summarize_transient_frame(&frame).unwrap();
        assert!(
            summary
                .bounded_text
                .starts_with("selected visual source 64x32;")
        );
        assert!(summary.bounded_text.contains("luminance="));
        assert!(summary.bounded_text.contains("detail="));
        assert!(summary.bounded_text.len() < 96);
        assert!(!summary.bounded_text.contains("255"));
    }

    #[test]
    fn blank_or_uniform_frame_is_a_protected_surface() {
        let frame = TransientPixelFrame {
            width: 8,
            height: 8,
            bytes: vec![0; 8 * 8 * 4],
        };
        assert_eq!(
            summarize_transient_frame(&frame).unwrap_err().kind,
            PixelErrorKind::ProtectedSurface
        );
    }

    #[test]
    fn transient_cpu_frame_is_zeroized_before_release() {
        let mut frame = synthetic_frame(8, 8);
        assert!(frame.bytes.iter().any(|byte| *byte != 0));
        frame.bytes.zeroize();
        assert!(frame.bytes.iter().all(|byte| *byte == 0));
        frame.bytes.clear();
    }

    #[test]
    fn disposable_capture_workers_are_process_wide_bounded() {
        let leases: Vec<_> = (0..MAXIMUM_DISPOSABLE_CAPTURE_WORKERS)
            .map(|_| CaptureWorkerLease::try_acquire().unwrap())
            .collect();
        assert_eq!(
            CaptureWorkerLease::try_acquire().unwrap_err().kind,
            PixelErrorKind::Unavailable
        );
        drop(leases);
        assert!(CaptureWorkerLease::try_acquire().is_ok());
    }

    #[test]
    fn revoked_and_cancelled_boundaries_fail_before_native_capture() {
        let revoked = AtomicBool::new(true);
        let active = CancellationToken::new();
        assert_eq!(
            check_capture_boundary(
                &revoked,
                Instant::now() + Duration::from_secs(1),
                &active,
                &active,
            )
            .unwrap_err()
            .kind,
            PixelErrorKind::BoundaryLost
        );
        revoked.store(false, Ordering::Release);
        active.cancel();
        assert_eq!(
            check_capture_boundary(
                &revoked,
                Instant::now() + Duration::from_secs(1),
                &active,
                &CancellationToken::new(),
            )
            .unwrap_err()
            .kind,
            PixelErrorKind::Cancelled
        );
    }

    #[test]
    #[ignore = "requires an interactive unlocked Windows graphics-capture session"]
    fn native_graphics_capture_support_probe_is_truthful() {
        let factory = NativePixelCaptureFactory::new();
        assert_eq!(
            factory.is_available(),
            GraphicsCaptureSession::IsSupported().unwrap_or(false)
        );
    }

    #[test]
    #[ignore = "requires the installed interactive picker fixture and an explicitly selected non-protected source"]
    fn native_picker_captures_exactly_one_bounded_transient_frame() {
        let factory = NativePixelCaptureFactory::new();
        assert!(factory.is_available());
        let cancellation = CancellationToken::new();
        let binding = factory
            .select(&cancellation)
            .unwrap()
            .expect("pick a source");
        let source = factory.open(&binding).unwrap();
        let summary = source
            .capture_one(
                Instant::now() + Duration::from_secs(5),
                &cancellation,
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(summary.bounded_text.starts_with("selected visual source "));
        factory.release(&binding).unwrap();
        assert!(factory.open(&binding).is_err());
    }
}
