import os
import tarfile

import paramiko
from scp import SCPClient

# Credits
HOST = "192.168.1.19"
USER = "voldemort"
PASS = "sassyboi"
LOCAL_DIR = "d:/Argus_AI"
REMOTE_DIR = "/home/voldemort/Argus_AI"

def create_tarball(source_dir, output_filename="argus_deploy.tar.gz"):
    print(f"[*] Compressing {source_dir} to {output_filename}...")
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
    return output_filename

def deploy():
    print(f"[*] Connecting to {USER}@{HOST}...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(HOST, username=USER, password=PASS)
        
        # 1. Transfer
        tar_file = create_tarball(LOCAL_DIR)
        print(f"[*] Uploading {tar_file}...")
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(tar_file, tar_file)
            
        # 2. Extract & Install
        print("[*] Extracting and Installing on Remote...")
        commands = [
            f"mkdir -p {REMOTE_DIR}",
            f"tar -xzf {tar_file} -C /home/voldemort/", # Extraction usually creates the subdir
            f"chmod +x {REMOTE_DIR}/scripts/install.sh",
            # We run with sudo -S to pipe password
            f"echo '{PASS}' | sudo -S {REMOTE_DIR}/scripts/install.sh" 
        ]
        
        for cmd in commands:
            print(f"    REMOTE_EXEC: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            # Wait for command to finish and capture output
            exit_status = stdout.channel.recv_exit_status()
            
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            
            if out: print(f"    [STDOUT] {out}")
            if err: print(f"    [STDERR] {err}")
            
    except Exception as e:
        print(f"[!] Deployment Failed: {e}")
    finally:
        ssh.close()
        # Cleanup local tar
        if os.path.exists("argus_deploy.tar.gz"):
            os.remove("argus_deploy.tar.gz")

if __name__ == "__main__":
    deploy()
