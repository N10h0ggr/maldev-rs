
#[cfg(test)]
mod integration_tests {
    use syscalls::*;
    #[test]
    fn declaration() {
        let nt_syscall = NtApiFunc::new();
    }
    fn getters() {
        let nt_syscall = NtApiFunc::new();
        let ssn = nt_syscall.get_function_ssn();
        let p_function = nt_syscall.get_function_pointer();
    }
}