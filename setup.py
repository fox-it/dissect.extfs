from setuptools import setup

setup(
    name="dissect.extfs",
    packages=["dissect.extfs"],
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
)
