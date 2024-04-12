
#!/usr/bin/python3

import os
from argparse import ArgumentParser
from ftplib import FTP
from functools import wraps
import ftplib
from datetime import date


UPLOAD_TYPE_BINARY = 'binary'
UPLOAD_TYPE_QNE = 'qne'
UPLOAD_TYPE_QTS = 'qts'


def set_arg_parser():
    parser = ArgumentParser()
    parser.add_argument("-n", "--name", required=True)
    parser.add_argument("-v", "--version", required=False)
    parser.add_argument("-c", "--compressed", required=True)
    parser.add_argument("--platform", required=False)
    parser.add_argument("-u", "--username", required=False)
    parser.add_argument("-p", "--password", required=False)
    parser.add_argument("-t", "--type",
                        choices=[UPLOAD_TYPE_BINARY, UPLOAD_TYPE_QNE, UPLOAD_TYPE_QTS],
                        default=UPLOAD_TYPE_BINARY)
    return parser


class FTPUploaderException(Exception):
    pass


class Decorators:
    FUNC_TYPE_ACTION = 'action'
    FUNC_TYPE_PROPERTY = 'property'
    FUNC_TYPE_RETURN = 'return'
    FUNC_TYPE_YIELD = 'yield'

    @classmethod
    def ensure_connection(cls, ftype):
        def real_decorator(func):
            @wraps(func)
            def wrapper(uploader, *args, **kwargs):
                uploader.retry_connection()
                return func(uploader, *args, **kwargs)

            @wraps(func)
            def yield_wrapper(uploader, *args, **kwargs):
                uploader.retry_connection()
                for item in func(uploader, *args, **kwargs):
                    yield item

            @wraps(func)
            def action_wrapper(uploader, *args, **kwargs):
                uploader.retry_connection()
                func(uploader, *args, **kwargs)

            FUNC_TYPE_MAP = {Decorators.FUNC_TYPE_RETURN: wrapper,
                             Decorators.FUNC_TYPE_PROPERTY: wrapper,
                             Decorators.FUNC_TYPE_YIELD: yield_wrapper,
                             Decorators.FUNC_TYPE_ACTION: action_wrapper}
            if ftype not in FUNC_TYPE_MAP:
                raise FTPUploaderException(f'Bad function type: {ftype}')
            return FUNC_TYPE_MAP[ftype]

        return real_decorator


class FTPUploader:
    DEF_HOST = '192.168.181.181'
    DEF_PORT = 21
    DEF_USERNAME = 'read'
    DEF_PASSWORD = 'read'
    DEF_BINARY_ROOT = '/QPKG/Binaries'
    DEF_QNE_RELEASE_ROOT = '/QNE/Release'
    DEF_DAILYBUILD_QVS_ROOT = '/QPKG/DailyBuild_QVS'

    def __init__(self, username, password, upload_type=UPLOAD_TYPE_BINARY):
        self.host = os.environ.get('PKG_FTP_HOST', FTPUploader.DEF_HOST)
        self.port = os.environ.get('PKG_FTP_PORT', FTPUploader.DEF_PORT)
        if username is not None:
            self.username = username
        else:
            self.username = os.environ.get(
                'FTP_USER', FTPUploader.DEF_USERNAME)
        if password is not None:
            self.password = password
        else:
            self.password = os.environ.get('FTP_PWD', FTPUploader.DEF_PASSWORD)
        self.ftp = None
        if upload_type == UPLOAD_TYPE_QNE:
            self.def_root = FTPUploader.DEF_QNE_RELEASE_ROOT
        elif upload_type == UPLOAD_TYPE_QTS:
            self.def_root = FTPUploader.DEF_DAILYBUILD_QVS_ROOT    
        else:
            self.def_root = FTPUploader.DEF_BINARY_ROOT

    def connect(self):
        try:
            self.ftp = FTP()
            self.ftp.connect(self.host, self.port, 30)
            self.ftp.login(self.username, self.password)
        except Exception:
            self.ftp = None
            raise FTPUploaderException(f'Failed to connect to {self.host}')

    @property
    def connected(self):
        if self.ftp is None:
            return False
        try:
            self.ftp.voidcmd('NOOP')
            return True
        except Exception:
            return False

    def retry_connection(self):
        if not self.connected:
            self.connect()

    @Decorators.ensure_connection(Decorators.FUNC_TYPE_ACTION)
    def chdir(self, path):
        target_path = os.path.join(self.def_root, path)
        try:
            self.ftp.cwd(target_path)
        except ftplib.error_perm:
            self.chdir('/'.join(path.split('/')[:-1]))
            self.ftp.mkd(target_path.split('/')[-1])
            self.ftp.cwd(target_path)

    @Decorators.ensure_connection(Decorators.FUNC_TYPE_ACTION)
    def upload(self, path, filename=None):
        if filename is None:
            print(f'upload: filename is None and path={path}')
            filename = os.path.basename(path)
        
        print(f'upload: filename={filename}')
        with open(path, 'rb') as fp:
            self.ftp.storbinary(f'STOR {filename}', fp)

    def __del__(self):
        if self.ftp is None:
            return
        self.ftp.close()


def get_upload_version(args_ver):
    if args_ver:
        return args_ver
    if (ver := os.environ.get('CI_BUILD_REF_NAME')) is not None:
        return ver
    return '9.9.9.9999'


def get_upload_path(name, version, platform):
    if name is 'QVS':
        date_path = date.today().strftime("%Y/%b/%d")
        print(f'get_upload_path: date_path={date_path}')
        return f'{date_path}'
    if platform is None:
        return f'{name}/{version}'
    return f'{name}/{version}/{platform}'


def get_upload_filename(name, version, platform):
    if name is 'QVS':
        return None
    if platform is None:
        return f'{name}_{version}_amd64.tar.gz'
    return f'{name}_{version}_{platform}_amd64.tar.gz'


if __name__ == '__main__':
    parser = set_arg_parser()
    args = parser.parse_args()

    version = get_upload_version(args.version)

    uploader = FTPUploader(args.username, args.password, upload_type=args.type)
    uploader.chdir(get_upload_path(args.name, version, args.platform))

    uploader.upload(
        args.compressed,
        get_upload_filename(args.name, version, args.platform))
