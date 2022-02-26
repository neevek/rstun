#[macro_export]
macro_rules! bail_with_log {
    ($($args:tt)*) => {
        error!($($args)*);
        bail!(format!($($args)*));
    };
}

macro_rules! unwrap_or_continue {
    ($opt:ident) => {
        if let Some(value) = $opt {
            value
        } else {
            continue;
        }
    };
}
