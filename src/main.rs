use std::{ptr::{null_mut, addr_of_mut}, ffi::CStr};
use errno::errno;
use libc::{strnlen, utsname, sethostname, uname, sleep, PROT_READ, PROT_WRITE, MAP_ANONYMOUS, MAP_STACK, MAP_PRIVATE, mmap, SIGCHLD, CLONE_NEWUTS, clone, waitpid, c_void, c_char};

const STACK_SIZE: usize = 1024 * 1024;

extern "C" fn cb(arg: *mut c_void) -> i32 {
    unsafe {
        let mut uts = utsname { sysname: [0; 65], nodename: [0; 65], release: [0; 65], version: [0; 65], machine: [0; 65], domainname: [0; 65] };
        let arg_len = strnlen(arg as *mut c_char, 64);
        let result = sethostname(arg as *mut c_char, arg_len);
        if result == -1 {
            let e = errno();
            let code = e.0;
            println!("Error {}: {}", code, e);
            panic!("failed to set hostname")
        }

        let result = uname(std::ptr::addr_of_mut!(uts) as *mut utsname);
        if result == -1 {
            let e = errno();
            let code = e.0;
            println!("Error {}: {}", code, e);
            panic!("failed to get uname")
        }
        let nodename = CStr::from_ptr(addr_of_mut!(uts.nodename) as *mut c_char).to_str().expect("failed");
        println!("uts.nodename in child: {}", nodename);
        sleep(3);
        0
    }
}

fn main() {
    if std::env::args().len() < 2 {
        println!("usage: {} hostname", std::env::args().nth(0).unwrap());
        return
    }
    let mut arg = std::env::args().nth(1).expect("failed to get first argument").into_bytes();
    arg.push(0);
    let child_stack_bottom = unsafe { mmap(null_mut(), STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0) };
    let child_stack_top = unsafe { child_stack_bottom.add(STACK_SIZE) };

    let pid = unsafe { clone(cb, child_stack_top, CLONE_NEWUTS | SIGCHLD, arg.as_mut_ptr() as *mut c_void) };
    if pid == -1 {
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed")
    }
    println!("clone returned {}", pid);
    unsafe { sleep(1) };

    let mut uts = utsname { sysname: [0; 65], nodename: [0; 65], release: [0; 65], version: [0; 65], machine: [0; 65], domainname: [0; 65] };
    let result = unsafe { uname(std::ptr::addr_of_mut!(uts) as *mut utsname) };
    if result == -1 {
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed to get parent's uname");
    }

    let nodename = unsafe { CStr::from_ptr(addr_of_mut!(uts.nodename) as *mut c_char) }.to_str().expect("failed");
    println!("uts.nodename in parent: {}", nodename);

    let result = unsafe { waitpid(pid, null_mut(), 0) };
    if result == -1 {
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed to wait for child pid")
    }
    println!("child has terminated")
}
