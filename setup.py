from setuptools import setup, find_packages

setup(
    name='DoKEBin',
    version='0.1',
    description='Hangul Word Document Malware Scanner',
    author='orca.eaa5a',
    author_email='dlfguswn@naver.com',
    url='https://github.com/orca-eaa5a/dokkaebi_scanner.git',
    python_requires  = '>=3',
    packages=find_packages(exclude = ['sample*', 'tests*', ]),
    package_data={
        "resource":[
            "/frame/rsrc/*",
            "/frame/main.ui",
        ],
        "yara":[
            "/pyhwpscan/scan/yara/eps/*.yar",
            "/pyhwpscan/scan/yara/jscript/*.yar",
            "/pyhwpscan/scan/yara/para_text/*.yar",
        ]
    },
    zip_safe=False,
    install_requires = [
        'EditorConfig',
        'hexdump',
        'jsbeautifier',
        'PySide2==5.15.2',
        'shiboken2==5.15.2',
        'six==1.16.0',
        #'yara==1.7.7', <-- manual install
    ],
    scripts=['main.py'],
)