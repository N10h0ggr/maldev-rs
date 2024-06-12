
#[cfg(test)]
mod integration_tests {

    use syscalls;
    const NT_CREATE_THREAD_EX_CRC32: u32 = 0xe2083cd5;

    #[test]
    fn test_direct_syscall() {
        prepare_syscall(hash);
        run_direct_syscall(those, are, some, params, 1);
    }

    #[test]
    fn test_indirect_syscall() {
        prepare_syscall(hash);
        run_indirect_syscall(those, are, some, params, 1, 2);
    }

    #[test]
    fn test_stack_syscall() {
        prepare_syscall(hash);
        run_stack_syscall(those, are, some, params, 1, 2, 3);
    }

}