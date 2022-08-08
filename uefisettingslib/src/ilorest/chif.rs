// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

use std::ffi::c_void;
use std::ffi::CStr;
use std::ptr;
use std::slice;

use anyhow::anyhow;
use anyhow::Result;
use libloading::Library;
use libloading::Symbol;
use log::debug;
use log::error;

type ByteArray = *mut u8;
type ChifString = *const i8;

type ChifInitializeFunction = fn() -> ();
type ChifCreateFunction = fn(*const *mut c_void) -> u32;
type ChifCloseFunction = fn(*mut c_void) -> u32;
type ChifPingFunction = fn(*mut c_void) -> u32;
type ChifSetRecvTimeoutFunction = fn(*mut c_void, u32) -> u32;
type ChifPacketExchangeFunction = fn(*mut c_void, *const u8, *mut u8, u32) -> u32;
type GetMaxBufferSizeFunction = fn() -> u32;
type GetReadRequestSizeFunction = fn() -> u32;
type GetResponseHeaderBlobSizeFunction = fn() -> u32;
type GetMaxReadSizeFunction = fn() -> u32;
type GetWriteRequestSizeFunction = fn() -> u32;
type GetMaxWriteSizeFunction = fn() -> u32;
type GetRestResponseFixedSizeFunction = fn() -> u32;
type RestImmediateFunction = fn(u32, ChifString, ChifString) -> ByteArray;
type RestImmediateBlobDescFunction = fn(ChifString, ChifString, ChifString) -> ByteArray;
type GetRestImmediateRequestSizeFunction = fn() -> u32;
type GetRestBlobRequestSizeFunction = fn() -> u32;
type WriteFragmentFunction = fn(u32, u32, ChifString, ChifString) -> ByteArray;
type CreateNotBlobEntryFunction = fn(ChifString, ChifString) -> ByteArray;
type ReadFragmentFunction = fn(u32, u32, ChifString, ChifString) -> ByteArray;
type GetCreateRequestSizeFunction = fn() -> u32;
type FinalizeBlobFunction = fn(ChifString, ChifString) -> ByteArray;
type GetFinalizeRequestSizeFunction = fn() -> u32;
type GetKeyInfoFunction = fn(ChifString, ChifString) -> ByteArray;
type DeleteBlobFunction = fn(ChifString, ChifString) -> ByteArray;
type GetDeleteRequestSizeFunction = fn() -> u32;
type GetInfoRequestSizeFunction = fn() -> u32;
type GetReadResponseSizeFunction = fn() -> u32;

// Status Code for Chif* functions. (on unix; NT has diff status codes but we don't care)
// We don't know what the rest of them mean cause the ilorest_chif.so lib is closed source.
const CHIF_STATUS_CODE_SUCCESS: u32 = 0;
// NoDriver = 19,
// AccessDenied = 13,
// InvalidArgument = 22 - not sure, just my guess after some experimentation

/// IloRestChif holds functions which are exported by ilorest_chif.so
/// ```no_run
/// let lib = get_lib("/usr/lib64/ilorest_chif.so")?;
/// let ilo = IloRestChif::new(&lib)?;
/// ```
/// This will load the ilorest_chif.so library, initialize it and create a new handle/connection to the ilo BMC.
pub struct IloRestChif<'a> {
    handle: *mut c_void,
    initialize: Symbol<'a, ChifInitializeFunction>,
    create: Symbol<'a, ChifCreateFunction>,
    close: Symbol<'a, ChifCloseFunction>,
    ping: Symbol<'a, ChifPingFunction>,
    packet_exchange: Symbol<'a, ChifPacketExchangeFunction>,
    set_recv_timeout: Symbol<'a, ChifSetRecvTimeoutFunction>,
    get_max_buffer_size: Symbol<'a, GetMaxBufferSizeFunction>,
    get_read_request_size: Symbol<'a, GetReadRequestSizeFunction>,
    get_response_header_blob_size: Symbol<'a, GetResponseHeaderBlobSizeFunction>,
    get_max_read_size: Symbol<'a, GetMaxReadSizeFunction>,
    get_max_write_size: Symbol<'a, GetMaxWriteSizeFunction>,
    get_write_request_size: Symbol<'a, GetWriteRequestSizeFunction>,
    get_rest_response_fixed_size: Symbol<'a, GetRestResponseFixedSizeFunction>,
    rest_immediate: Symbol<'a, RestImmediateFunction>,
    rest_immediate_blob_desc: Symbol<'a, RestImmediateBlobDescFunction>,
    get_rest_immediate_request_size: Symbol<'a, GetRestImmediateRequestSizeFunction>,
    get_rest_blob_request_size: Symbol<'a, GetRestBlobRequestSizeFunction>,
    create_not_blobentry: Symbol<'a, CreateNotBlobEntryFunction>,
    write_fragment: Symbol<'a, WriteFragmentFunction>,
    read_fragment: Symbol<'a, ReadFragmentFunction>,
    finalize_blob: Symbol<'a, FinalizeBlobFunction>,
    get_finalize_request_size: Symbol<'a, GetFinalizeRequestSizeFunction>,
    get_create_request_size: Symbol<'a, GetCreateRequestSizeFunction>,
    get_key_info: Symbol<'a, GetKeyInfoFunction>,
    delete_blob: Symbol<'a, DeleteBlobFunction>,
    get_delete_request_size: Symbol<'a, GetDeleteRequestSizeFunction>,
    get_info_request_size: Symbol<'a, GetInfoRequestSizeFunction>,
    get_read_response_size: Symbol<'a, GetReadResponseSizeFunction>,
}

impl<'a> IloRestChif<'a> {
    pub fn new(lib: &'a Library) -> Result<Self> {
        // SAFETY: We need unsafe here because we are calling a C/C++ dynamic library at runtime
        // and interfacing with C/C++ code in Rust requires unsafe.

        // We are using the libloading crate so the compiler will ensure that the loaded function will not
        // outlive the Library from which it comes, preventing the most common memory-safety issues.

        let lib_funcs = unsafe {
            let initialize: Symbol<ChifInitializeFunction> = lib.get(b"ChifInitialize")?;
            let create: Symbol<ChifCreateFunction> = lib.get(b"ChifCreate")?;
            let close: Symbol<ChifCloseFunction> = lib.get(b"ChifClose")?;
            let ping: Symbol<ChifPingFunction> = lib.get(b"ChifPing")?;
            let packet_exchange: Symbol<ChifPacketExchangeFunction> =
                lib.get(b"ChifPacketExchange")?;
            let set_recv_timeout: Symbol<ChifSetRecvTimeoutFunction> =
                lib.get(b"ChifSetRecvTimeout")?;
            let get_max_buffer_size: Symbol<GetMaxBufferSizeFunction> =
                lib.get(b"get_max_buffer_size")?;
            let get_read_request_size: Symbol<GetReadRequestSizeFunction> =
                lib.get(b"size_of_readRequest")?;
            let get_response_header_blob_size: Symbol<GetResponseHeaderBlobSizeFunction> =
                lib.get(b"size_of_responseHeaderBlob")?;
            let get_max_read_size: Symbol<GetMaxReadSizeFunction> = lib.get(b"max_read_size")?;
            let get_max_write_size: Symbol<GetMaxWriteSizeFunction> = lib.get(b"max_write_size")?;
            let get_write_request_size: Symbol<GetWriteRequestSizeFunction> =
                lib.get(b"size_of_writeRequest")?;
            let get_rest_response_fixed_size: Symbol<GetRestResponseFixedSizeFunction> =
                lib.get(b"size_of_restResponseFixed")?;
            let rest_immediate: Symbol<RestImmediateFunction> = lib.get(b"rest_immediate")?;
            let rest_immediate_blob_desc: Symbol<RestImmediateBlobDescFunction> =
                lib.get(b"rest_immediate_blobdesc")?;
            let get_rest_immediate_request_size: Symbol<GetRestImmediateRequestSizeFunction> =
                lib.get(b"size_of_restImmediateRequest")?;
            let get_rest_blob_request_size: Symbol<GetRestBlobRequestSizeFunction> =
                lib.get(b"size_of_restBlobRequest")?;
            let create_not_blobentry: Symbol<CreateNotBlobEntryFunction> =
                lib.get(b"create_not_blobentry")?;
            let write_fragment: Symbol<WriteFragmentFunction> = lib.get(b"write_fragment")?;
            let read_fragment: Symbol<ReadFragmentFunction> = lib.get(b"read_fragment")?;
            let finalize_blob: Symbol<FinalizeBlobFunction> = lib.get(b"finalize_blob")?;
            let get_finalize_request_size: Symbol<GetFinalizeRequestSizeFunction> =
                lib.get(b"size_of_finalizeRequest")?;
            let get_create_request_size: Symbol<GetCreateRequestSizeFunction> =
                lib.get(b"size_of_createRequest")?;
            let get_key_info: Symbol<GetKeyInfoFunction> = lib.get(b"get_info")?;
            let get_info_request_size: Symbol<GetInfoRequestSizeFunction> =
                lib.get(b"size_of_infoRequest")?;
            let get_read_response_size: Symbol<GetReadResponseSizeFunction> =
                lib.get(b"size_of_readResponse")?;
            let delete_blob: Symbol<DeleteBlobFunction> = lib.get(b"delete_blob")?;
            let get_delete_request_size: Symbol<GetDeleteRequestSizeFunction> =
                lib.get(b"size_of_deleteRequest")?;

            let handle = ptr::null_mut();

            IloRestChif {
                handle,
                initialize,
                create,
                close,
                ping,
                packet_exchange,
                set_recv_timeout,
                get_max_buffer_size,
                get_read_request_size,
                get_response_header_blob_size,
                get_max_read_size,
                get_max_write_size,
                get_write_request_size,
                get_rest_response_fixed_size,
                rest_immediate,
                rest_immediate_blob_desc,
                get_rest_immediate_request_size,
                get_rest_blob_request_size,
                create_not_blobentry,
                write_fragment,
                read_fragment,
                finalize_blob,
                get_finalize_request_size,
                get_create_request_size,
                get_key_info,
                get_info_request_size,
                get_read_response_size,
                delete_blob,
                get_delete_request_size,
            }
        };

        // Create a handle, initialize library and create a connection.

        (lib_funcs.initialize)();

        let status_code = (lib_funcs.create)(&(lib_funcs.handle));
        debug!("Create status code is {}", status_code);

        if status_code != CHIF_STATUS_CODE_SUCCESS {
            return Err(anyhow!(format!(
                "Unexpected Status Code: {} during create",
                status_code
            )));
        }

        Ok(lib_funcs)
    }
}

impl<'a> Drop for IloRestChif<'a> {
    fn drop(&mut self) {
        let status_code = (self.close)(self.handle);
        debug!("Close status code is {}", status_code);

        if status_code != CHIF_STATUS_CODE_SUCCESS {
            error!("Unexpected Status Code: {} during close", status_code)
        }
    }
}

impl<'a> IloRestChifInterface for IloRestChif<'a> {
    fn ping(&self) -> Result<(), u32> {
        let status_code = (self.ping)(self.handle);
        debug!("Ping status code is {}", status_code);

        if status_code != CHIF_STATUS_CODE_SUCCESS {
            return Err(status_code);
        }
        Ok(())
    }

    fn exchange_packet(&self, send_buf: &[u8]) -> Result<Vec<u8>, u32> {
        let max_buffer_size = (self.get_max_buffer_size)();
        let mut recv_buf: Vec<u8> = vec![0; max_buffer_size as usize];

        let status_code = (self.packet_exchange)(
            self.handle,
            send_buf.as_ptr(),
            recv_buf.as_mut_ptr(),
            max_buffer_size,
        );

        debug!("Packet Exchange Status Code is {}", status_code);

        if status_code != CHIF_STATUS_CODE_SUCCESS {
            return Err(status_code);
        }

        Ok(recv_buf)
    }

    fn set_recv_timeout(&self, timeout: u32) -> Result<(), u32> {
        let status_code = (self.set_recv_timeout)(self.handle, timeout);
        debug!("Set Recv Timeout status code is {}", status_code);

        if status_code != CHIF_STATUS_CODE_SUCCESS {
            return Err(status_code);
        }
        Ok(())
    }

    fn get_max_buffer_size(&self) -> u32 {
        (self.get_max_buffer_size)()
    }

    fn get_read_request_size(&self) -> u32 {
        (self.get_read_request_size)()
    }

    fn get_response_header_blob_size(&self) -> u32 {
        (self.get_response_header_blob_size)()
    }

    fn get_max_read_size(&self) -> u32 {
        (self.get_max_read_size)()
    }

    fn get_max_write_size(&self) -> u32 {
        (self.get_max_write_size)()
    }

    fn get_write_request_size(&self) -> u32 {
        (self.get_write_request_size)()
    }

    fn get_rest_response_fixed_size(&self) -> u32 {
        (self.get_rest_response_fixed_size)()
    }

    fn prepare_immediate_request(
        &self,
        request_body_and_header_size: u32,
        response_key: &CStr,
        namespace: &CStr,
    ) -> &'a [u8] {
        // SAFETY:
        // ilorest_chif.so sends us a pointer to an array of bytes. Since we know the size we can convert it into &[u8]
        // using the unsafe function slice::from_raw_parts().

        // However this should be okay because when handle goes out of scope, it calls ilorest_chif.so's close()
        // which (according to some experimentation) releases memory referenced by this pointer.
        // The compiler doesn't allow this slice to be referenced after lib and handle have gone out of scope.

        unsafe {
            let tmp_struct_pointer = (self.rest_immediate)(
                request_body_and_header_size,
                response_key.as_ptr(),
                namespace.as_ptr(),
            );
            slice::from_raw_parts(
                tmp_struct_pointer,
                (self.get_rest_immediate_request_size)() as usize,
            )
        }
    }

    fn prepare_blob_request(
        &self,
        request_key: &CStr,
        response_key: &CStr,
        namespace: &CStr,
    ) -> &'a [u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer = (self.rest_immediate_blob_desc)(
                request_key.as_ptr(),
                response_key.as_ptr(),
                namespace.as_ptr(),
            );
            slice::from_raw_parts(
                tmp_struct_pointer,
                (self.get_rest_blob_request_size)() as usize,
            )
        }
    }

    fn get_immediate_request_size(&self) -> u32 {
        (self.get_rest_immediate_request_size)()
    }

    fn get_blob_request_size(&self) -> u32 {
        (self.get_rest_blob_request_size)()
    }

    fn prepare_new_blob_entry(&self, request_key: &CStr, namespace: &CStr) -> &[u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer =
                (self.create_not_blobentry)(request_key.as_ptr(), namespace.as_ptr());
            slice::from_raw_parts(
                tmp_struct_pointer,
                (self.get_create_request_size)() as usize,
            )
        }
    }

    fn prepare_write_fragment(
        &self,
        write_block_size: u32,
        count: u32,
        request_key: &CStr,
        namespace: &CStr,
    ) -> &'a [u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer = (self.write_fragment)(
                write_block_size,
                count,
                request_key.as_ptr(),
                namespace.as_ptr(),
            );
            slice::from_raw_parts(tmp_struct_pointer, (self.get_write_request_size)() as usize)
        }
    }

    fn prepare_read_fragment(
        &self,
        read_block_size: u32,
        count: u32,
        response_key: &CStr,
        namespace: &CStr,
    ) -> &'a [u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer = (self.read_fragment)(
                read_block_size,
                count,
                response_key.as_ptr(),
                namespace.as_ptr(),
            );
            slice::from_raw_parts(tmp_struct_pointer, (self.get_read_request_size)() as usize)
        }
    }

    fn finalize_blob_write(&self, request_key: &CStr, namespace: &CStr) -> &[u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer = (self.finalize_blob)(request_key.as_ptr(), namespace.as_ptr());
            slice::from_raw_parts(
                tmp_struct_pointer,
                (self.get_finalize_request_size)() as usize,
            )
        }
    }

    fn get_finalize_request_size(&self) -> u32 {
        (self.get_finalize_request_size)()
    }

    fn get_create_request_size(&self) -> u32 {
        (self.get_create_request_size)()
    }

    fn get_key_info(&self, response_key: &CStr, namespace: &CStr) -> &'a [u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer = (self.get_key_info)(response_key.as_ptr(), namespace.as_ptr());
            slice::from_raw_parts(tmp_struct_pointer, (self.get_info_request_size)() as usize)
        }
    }

    fn get_info_request_size(&self) -> u32 {
        (self.get_info_request_size)()
    }

    fn get_read_response_size(&self) -> u32 {
        (self.get_read_response_size)()
    }

    fn prepare_delete_blob(&self, key: &CStr, namespace: &CStr) -> &'a [u8] {
        // SAFETY: Look at the safety comment in rest_immediate()
        unsafe {
            let tmp_struct_pointer = (self.delete_blob)(key.as_ptr(), namespace.as_ptr());
            slice::from_raw_parts(
                tmp_struct_pointer,
                (self.get_delete_request_size)() as usize,
            )
        }
    }

    fn get_delete_request_size(&self) -> u32 {
        (self.get_delete_request_size)()
    }
}

/// IloRestChifInterface is a rusty interface to ilorest_chif functions
pub trait IloRestChifInterface {
    fn ping(&self) -> Result<(), u32>;
    fn exchange_packet(&self, send_buf: &[u8]) -> Result<Vec<u8>, u32>;
    fn set_recv_timeout(&self, timeout: u32) -> Result<(), u32>;
    fn get_max_buffer_size(&self) -> u32;
    fn get_read_request_size(&self) -> u32;
    fn get_response_header_blob_size(&self) -> u32;
    fn get_max_read_size(&self) -> u32;
    fn get_max_write_size(&self) -> u32;
    fn get_write_request_size(&self) -> u32;
    fn get_rest_response_fixed_size(&self) -> u32;
    fn prepare_immediate_request(
        &self,
        request_body_and_header_size: u32,
        response_key: &CStr,
        namespace: &CStr,
    ) -> &[u8];
    fn prepare_blob_request(
        &self,
        request_key: &CStr,
        response_key: &CStr,
        namespace: &CStr,
    ) -> &[u8];
    fn get_immediate_request_size(&self) -> u32;
    fn get_blob_request_size(&self) -> u32;
    fn prepare_new_blob_entry(&self, request_key: &CStr, namespace: &CStr) -> &[u8];
    fn prepare_write_fragment(
        &self,
        write_block_size: u32,
        count: u32,
        request_key: &CStr,
        namespace: &CStr,
    ) -> &[u8];
    fn prepare_read_fragment(
        &self,
        read_block_size: u32,
        count: u32,
        response_key: &CStr,
        namespace: &CStr,
    ) -> &[u8];
    fn finalize_blob_write(&self, request_key: &CStr, namespace: &CStr) -> &[u8];
    fn get_finalize_request_size(&self) -> u32;
    fn get_create_request_size(&self) -> u32;
    fn get_key_info(&self, response_key: &CStr, namespace: &CStr) -> &[u8];
    fn get_info_request_size(&self) -> u32;
    fn get_read_response_size(&self) -> u32;
    fn prepare_delete_blob(&self, key: &CStr, namespace: &CStr) -> &[u8];
    fn get_delete_request_size(&self) -> u32;
}

pub fn get_lib(libpath: &str) -> Result<Library> {
    // SAFETY: We need unsafe here because we are calling a C/C++ dynamic library at runtime
    // and interfacing with C/C++ code in Rust requires unsafe.
    // Libloading + the compiler will ensure that the loaded symbols will not
    // outlive the Library, preventing the most common memory-safety issues.
    Ok(unsafe { Library::new(libpath)? })
}
