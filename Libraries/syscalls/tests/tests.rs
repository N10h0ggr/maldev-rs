#[cfg(test)]
mod integration_tests {
    use crate::NtApiFunc;

    #[test]
    fn declaration() {
        let nt_syscall = NtApiFunc::new();
    }
}