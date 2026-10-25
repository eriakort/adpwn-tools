"""Setup file – makes adpwn-tools pip-installable."""
from setuptools import setup, find_packages

setup(
    name="adpwn-tools",
    version="1.0.0",
    description="BloodyAD + aclpwn AD privilege-escalation MCP toolkit",
    packages=find_packages(include=["adpwn", "adpwn.*", "tools", "tools.*"]),
    py_modules=["adpwn_tools", "adpwn_cli", "autobloody_tool", "bloodyad_tool"],
    python_requires=">=3.9",
    install_requires=[
        "ldap3>=2.9",
        "bloodyAD",
    ],
    extras_require={
        "autobloody": ["autobloody"],
    },
    entry_points={
        "console_scripts": [
            "adpwn=adpwn_cli:main",
        ],
    },
)
