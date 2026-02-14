#include <pybind11/pybind11.h>
#include <pybind11/stl.h> // Required for std::vector conversion to Python lists
#include "FlowAggregator.hpp"

namespace py = pybind11;

// This macro defines the Python module named 'flow_agg_cpp'
PYBIND11_MODULE(flow_agg_cpp, m) {
    // Optional module documentation string
    m.doc() = "pybind11 C++ module for high-speed network flow aggregation.";

    // Expose the FlowAggregator class to Python
    py::class_<FlowAggregator>(m, "FlowAggregator")
        // Expose the constructor, allowing Python to create objects like:
        // aggregator = flow_agg_cpp.FlowAggregator(window_ms=1000)
        .def(py::init<long long>(), py::arg("window_ms") = 1000, 
             "Initializes the flow aggregator with a window duration in milliseconds.")
        
        // Expose the update_flow method
        // py::arg ensures argument names are visible in Python help/docs
        .def("update_flow", &FlowAggregator::update_flow, 
             py::arg("flow_id"), py::arg("packet_size"), py::arg("protocol"), py::arg("current_time_ms"),
             "Updates the state of a single flow with new packet data.")
        
        // Expose the check_and_flush_window method
        .def("check_and_flush_window", &FlowAggregator::check_and_flush_window, 
             py::arg("current_time_ms"),
             "Checks for window expiry and returns all completed feature vectors.");
}