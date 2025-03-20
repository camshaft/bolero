use crate::{Driver, TypeGenerator};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};

macro_rules! impl_generator {
    ($ty:ty, | $driver:ident | $produce:expr) => {
        impl TypeGenerator for $ty {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                driver.enter_product::<Self, _, _>(|$driver| $produce)
            }
        }
    };
}

impl_generator!(Ipv4Addr, |driver| {
    let v: u32 = driver.produce()?;
    Some(Ipv4Addr::from(v))
});
impl_generator!(Ipv6Addr, |driver| {
    let v: u128 = driver.produce()?;
    Some(Ipv6Addr::from(v))
});
impl_generator!(SocketAddrV4, |driver| {
    let ip = driver.produce()?;
    let port = driver.produce()?;
    Some(SocketAddrV4::new(ip, port))
});
impl_generator!(SocketAddrV6, |driver| {
    let ip = driver.produce()?;
    let port = driver.produce()?;
    let flow_info = driver.produce()?;
    let scope_id = driver.produce()?;
    Some(SocketAddrV6::new(ip, port, flow_info, scope_id))
});
impl_generator!(SocketAddr, |driver| {
    let ip = driver.produce()?;
    let port = driver.produce()?;
    Some(SocketAddr::new(ip, port))
});

impl TypeGenerator for IpAddr {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.enter_sum::<Self, _, _>(Some(&["V4", "V6"]), 2, 0, |driver, idx| match idx {
            0 => Some(IpAddr::V4(driver.produce()?)),
            1 => Some(IpAddr::V6(driver.produce()?)),
            _ => None,
        })
    }
}

impl TypeGenerator for Shutdown {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.enter_sum::<Self, _, _>(Some(&["Read", "Write", "Both"]), 3, 0, |_driver, idx| {
            match idx {
                0 => Some(Shutdown::Read),
                1 => Some(Shutdown::Write),
                2 => Some(Shutdown::Both),
                _ => None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_generator {
        ($name:ident, $ty:ty) => {
            #[test]
            fn $name() {
                let _ = generator_test!(produce::<$ty>());
            }
        };
    }

    test_generator!(test_ipv4addr, Ipv4Addr);
    test_generator!(test_ipv6addr, Ipv6Addr);
    test_generator!(test_ipaddr, IpAddr);
    test_generator!(test_socketaddrv4, SocketAddrV4);
    test_generator!(test_socketaddrv6, SocketAddrV6);
    test_generator!(test_socketaddr, SocketAddr);
    test_generator!(test_shutdown, Shutdown);
}
