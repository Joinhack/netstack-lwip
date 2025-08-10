use std::{net::IpAddr, os::raw::c_void, pin::{pin, Pin}, sync::Once, task::{Context, Poll, Waker}};

use crate::{
    lwip::{
        err_enum_t_ERR_OK, err_t, icmp_pcb, icmp_sendto, ip_addr_t, pbuf, pbuf_alloc_reference, pbuf_copy_partial, pbuf_free, pbuf_type_PBUF_REF, set_icmp_ping_pcb
    }, 
    util
};
use futures::{io, Stream};
use tokio::sync::mpsc::{
    channel, Receiver, Sender
};

pub extern "C" fn icmp_ping(
    arg: *mut ::std::os::raw::c_void,
    _pcb: *mut icmp_pcb,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    dest_addr: *const ip_addr_t,
    _type_: u8,
    _code: u8,
) {
    unsafe  {
        let tot_len = std::ptr::read_unaligned(p).tot_len;
        let mut buf: Vec<u8> = Vec::with_capacity(tot_len as _);
        buf.set_len(tot_len as _);
        pbuf_copy_partial(p, buf.as_mut_ptr()  as *mut _, tot_len, 0);
        let addr = util::to_addr(&*addr);
        let dst_addr = util::to_addr(&*dest_addr);
        let icmp_ping = &mut *(arg as *mut IcmpPing);
        if let Err(e) = icmp_ping.tx.try_send((buf, addr, dst_addr)) {
            log::error!("Failed to send ICMP ping packet: {}", e);
        }
        if let Some(ref waker) = icmp_ping.waker {
            waker.wake_by_ref();
        }
    };
}

type IcmpPkt = (Vec<u8>, IpAddr, IpAddr);

pub struct IcmpPing {
    waker: Option<Waker>,
    tx: Sender<IcmpPkt>,
    rx: Receiver<IcmpPkt>,
}

impl IcmpPing {
    pub fn new(buf_size: usize) -> Pin<Box<Self>> {
        let (tx, rx) = channel(buf_size);
        static INIT: Once = Once::new();
        let me = Box::pin(Self {
            tx,
            rx,
            waker: None,
        });
        INIT.call_once(|| {
            unsafe {
                set_icmp_ping_pcb(Some(icmp_ping), &*me as *const IcmpPing as *mut  c_void );   
            }
        });
        me
    }

    pub fn split(self: Pin<Box<Self>>) -> (SendHalf, RecvHalf) {
        (SendHalf{}, RecvHalf{icmp_ping: self})
    }
   
}

impl Stream for IcmpPing {
    type Item = IcmpPkt;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.rx.poll_recv(cx) {
            Poll::Ready(opt) => Poll::Ready(opt),
            Poll::Pending => {
                this.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

pub struct SendHalf;

impl SendHalf {
    pub fn send(&self, data: Vec<u8>, src_addr: IpAddr, dst_addr: IpAddr) -> io::Result<()> {
        let _g = super::LWIP_MUTEX.lock();
        unsafe {
            let pbuf =
                pbuf_alloc_reference(data.as_ptr() as *mut _, data.len() as _, pbuf_type_PBUF_REF);
            let src_ip = util::to_ip_addr_t(src_addr);
            let dst_ip = util::to_ip_addr_t(dst_addr);
            let err = icmp_sendto(
                pbuf,
                &src_ip as *const  _,
                &dst_ip as *const  _,
            );
            pbuf_free(pbuf);
            if err != err_enum_t_ERR_OK as err_t {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("icmp_sendto error: {}", err),
                ));
            };
        }
        Ok(())
    }
    
}

pub struct RecvHalf {
    icmp_ping: Pin<Box<IcmpPing>>,
}

impl Stream for RecvHalf {
    type Item = IcmpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let RecvHalf { ref mut icmp_ping } = &mut *self;
        pin!(icmp_ping).poll_next(cx)
    }
}