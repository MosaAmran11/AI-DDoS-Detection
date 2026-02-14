from setuptools import setup, Extension
import pybind11
import os

# 1. Define the C++ extension module
cpp_module = Extension(
    # The name of the Python module that will be imported (import flow_agg_cpp)
    'flow_agg_cpp',

    # List of all C++ source files needed
    sources=[
        './cpp/FlowAggregator.cpp',
        './cpp/FlowAggregator_bindings.cpp'
    ],

    # Tell the compiler where to find the pybind11 header files
    include_dirs=[
        pybind11.get_include(),
        os.path.abspath(os.path.dirname(__file__))  # For FlowAggregator.hpp
    ],

    # Specify the language standard (pybind11 requires C++17 or newer)
    language='c++',
    extra_compile_args=['-std=c++17'],
)

# 2. Package configuration
setup(
    name='flow_agg_cpp',
    version='1.0',
    description='C++ acceleration for DDoS feature aggregation.',
    ext_modules=[cpp_module],
    # Ensure pybind11 is installed before building
    install_requires=['pybind11'],
)
