#![no_std]

macro_rules! microserde {
    ($(pub struct $name:ident $(<$lt:lifetime>)? { $( pub $field:ident: $typ:ty, )*} )*) => {
        $(
            pub struct $name $(<$lt>)? {
                $( pub $field: $typ,)*
            }
            impl<'a> Data<'a> for $name $(<$lt>)? {
                const SIZE: usize = 0 $( + <$typ as Data<'a>>::SIZE )*;

                fn write<'b>(&self, buf: &'b mut [u8]) -> Option<&'b mut [u8]> {
                    $(
                        let buf = self.$field.write(buf)?;
                    )*
                    Some(buf)
                }
                fn decode(data: &'a [u8]) -> Option<(Self, &'a [u8])> {
                    $(
                        let ($field, data) = <$typ>::decode(data)?;
                    )*
                    Some(($name {
                        $( $field, )*
                    }, data))
                }
            }
        )*
    };
}

microserde! {
    pub struct PreAuthReq<'a> {
        pub a_pub: [u8; 512],
        pub username: &'a str,
    }

    pub struct PreAuthResp {
        pub salt: [u8; 32],
        pub b_pub: [u8; 512],
        pub key: [u8; 8],
    }

    pub struct AuthReq {
        pub proof: [u8; 64],
        pub key: [u8; 8],
    }

    pub struct AuthResponse {
        pub proof: [u8; 64],
    }

    pub struct RegisterReq<'a> {
        pub username: &'a str,
        pub salt: [u8; 32],
        pub verifier: [u8; 512],
    }
}

pub trait Data<'a>: Sized {
    const SIZE: usize;
    fn write<'b>(&self, buf: &'b mut [u8]) -> Option<&'b mut [u8]>;
    fn decode(data: &'a [u8]) -> Option<(Self, &'a [u8])>;

    fn encode<'b>(&self, buf: &'b mut [u8]) -> Option<&'b [u8]> {
        let full = buf.len();
        let rest = self.write(buf)?;
        let written = full - rest.len();
        Some(&buf[..written])
    }
}
impl<'a> Data<'a> for &'a str {
    const SIZE: usize = 128;
    fn write<'b>(&self, buf: &'b mut [u8]) -> Option<&'b mut [u8]> {
        if self.len() > u16::MAX as usize {
            return None;
        }
        let len = self.len() as u16;
        let (dst, rest) = buf.split_at_mut_checked(2)?;
        dst.copy_from_slice(&len.to_le_bytes());

        let (dst, rest) = rest.split_at_mut_checked(self.len())?;
        dst.copy_from_slice(self.as_bytes());

        Some(rest)
    }
    fn decode(data: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let (len, rest) = data.split_at_checked(2)?;
        let len = u16::from_le_bytes(len.try_into().unwrap()) as usize;
        let (s, rest) = rest.split_at_checked(len)?;
        let s = core::str::from_utf8(s).ok()?;
        Some((s.into(), rest))
    }
}

impl<'a, const N: usize> Data<'a> for [u8; N] {
    const SIZE: usize = N;
    fn write<'b>(&self, buf: &'b mut [u8]) -> Option<&'b mut [u8]> {
        let (dst, rest) = buf.split_at_mut_checked(N)?;
        dst.copy_from_slice(self);
        Some(rest)
    }
    fn decode(data: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let (src, rest) = data.split_at_checked(N)?;
        let mut buf = [0; N];
        buf.copy_from_slice(src);
        Some((buf, rest))
    }
}
