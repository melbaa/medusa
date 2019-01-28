from setuptools import setup

setup(
    name='melbalabs_medusa',
    packages=['melbalabs.medusa'],
    include_package_data=True,
    zip_safe=False,
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    entry_points={
        'console_scripts': ['medusa=melbalabs.medusa.medusa:main'],
    }
)
