//! String types whose well-known values are enum variants.

/// Defines a string type whose well-known values are unit variants, so
/// that copying one allocates nothing, while any other value is kept as
/// it is in `Other`, and the empty string is `Unset`. Values compare,
/// print and serialize as the string.
macro_rules! known_strings {
    ($(#[$m:meta])* $t:ident { $($v:ident => $s:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Default)]
        pub enum $t {
            /// None given: the empty string, as Go leaves it.
            #[default]
            Unset,
            $($v,)*
            Other(String),
        }

        impl $t {
            pub fn as_str(&self) -> &str {
                match self {
                    $t::Unset => "",
                    $($t::$v => $s,)*
                    $t::Other(s) => s,
                }
            }

            pub fn is_empty(&self) -> bool {
                self.as_str().is_empty()
            }
        }

        impl From<&str> for $t {
            fn from(s: &str) -> Self {
                match s {
                    "" => $t::Unset,
                    $($s => $t::$v,)*
                    s => $t::Other(s.into()),
                }
            }
        }

        impl From<String> for $t {
            fn from(s: String) -> Self {
                match s.as_str() {
                    "" => $t::Unset,
                    $($s => $t::$v,)*
                    _ => $t::Other(s),
                }
            }
        }

        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl PartialEq<&str> for $t {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl ::std::fmt::Display for $t {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::serde::Serialize for $t {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> ::std::result::Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $t {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> ::std::result::Result<Self, D::Error> {
                <String as ::serde::Deserialize>::deserialize(d).map($t::from)
            }
        }
    };
}
