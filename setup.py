from setuptools import setup

import rulecata

setup(
    name="rulecata",
    version=rulecata.version,
    description="Suricata Rule Updater",
    author="Jason Ish",
    author_email="ish@unx.ca",
    packages=[
        "rulecata",
        "rulecata.compat",
        "rulecata.compat.argparse",
    ],
    url="https://github.com/jasonish/rulecata",
    license="GPLv2",
    classifiers=[
        'License :: OSI Approved :: GPLv2 License',
    ],
    scripts = [
        "bin/rulecata",
    ],
)
