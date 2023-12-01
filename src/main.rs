use std::{ptr::{null_mut, addr_of_mut, null}, ffi::{CStr, CString}, process::Command};
use errno::errno;
use libc::{strnlen, utsname, sethostname, uname, PROT_READ, PROT_WRITE, MAP_ANONYMOUS, MAP_STACK, MAP_PRIVATE, mmap, SIGCHLD, CLONE_NEWUTS, clone, waitpid, c_void, c_char, execv, chdir, chroot};

const STACK_SIZE: usize = 1024 * 1024;

#[repr(C)]
#[derive(Debug,Clone)]
struct ChildArgs {
    hostname: CString,
    chroot_path: CString,
}

fn chroot_to(path: &CStr) {
    if -1 == unsafe { chroot(path.as_ptr() as *mut i8) } {
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed to chroot")
    }
    let root = CString::new("/").expect("CString::new failed");
    if -1 == unsafe { chdir(root.as_ptr()) } {
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed to chdir")
    }
}

extern "C" fn cb(arg: *mut c_void) -> i32 {
    unsafe {
        let arg = arg as *mut ChildArgs;
        chroot_to(&(*arg).chroot_path);

        let mut uts = utsname { sysname: [0; 65], nodename: [0; 65], release: [0; 65], version: [0; 65], machine: [0; 65], domainname: [0; 65] };
        let arg_len = strnlen((*arg).hostname.as_ptr() as *mut c_char, 64);
        let result = sethostname((*arg).hostname.as_ptr() as *mut c_char, arg_len);
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

        let prog = CString::new("/bin/bash").expect("failed to form CString");
        let argv = [prog.as_ptr(), null()];
        execv(prog.as_ptr() as *const i8, argv.as_ptr()  as *const *const i8);
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed to exec /bin/bash")
    }
}

fn main() {
    if std::env::args().len() < 3 {
        println!("usage: {} hostname chroot_path", std::env::args().nth(0).unwrap());
        return
    }
    let hostname = CString::new(std::env::args().nth(1).expect("failed to get first argument")).expect("CString::new failed");
    let chroot_path = CString::new(std::env::args().nth(2).expect("failed to get chroot path")).expect("CString::new failed");
    let child_stack_bottom = unsafe { mmap(null_mut(), STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0) };
    let child_stack_top = unsafe { child_stack_bottom.add(STACK_SIZE) };
    let mut arg = ChildArgs { hostname, chroot_path };
    let pid = unsafe { clone(cb, child_stack_top, CLONE_NEWUTS | SIGCHLD, addr_of_mut!(arg) as *mut c_void) };
    if pid == -1 {
        let e = errno();
        let code = e.0;
        println!("Error {}: {}", code, e);
        panic!("failed")
    }

    Command::new("bash")
            .arg("-c")
            .arg(format!("echo '0 0 4294967295' > /proc/{}/uid_map", pid))
            .output()
            .expect("failed to exec cmd");
    Command::new("bash")
            .arg("-c")
            .arg(format!("echo '0 0 4294967295' > /proc/{}/gid_map", pid))
            .output()
            .expect("failed to exec cmd");

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
