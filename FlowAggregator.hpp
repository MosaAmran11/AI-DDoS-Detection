#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <chrono>
#include <cmath> // For std::sqrt

// Based on feature_config.py, we have 10 features.
constexpr size_t FEATURE_VECTOR_SIZE = 10; 

/**
 * @brief Represents the state of a single flow (Source/Dest IP/Port, Protocol).
 * This structure holds the raw metrics aggregated over the time window.
 */
struct FlowState {
    // --- Flow Identification and Timing ---
    std::string flow_id;
    long long start_time_ms = 0; // Time the flow was first seen in the current window
    
    // --- Raw Aggregated Features (for speed) ---
    int packet_count = 0;
    long long total_bytes = 0;
    long long sum_sq_pkt_size = 0; // For standard deviation calculation
    
    // Protocol flags (can be set only once on creation)
    bool is_tcp = false;
    bool is_udp = false;
    bool is_icmp = false;
};

/**
 * @brief High-speed class for managing and aggregating network flow features 
 * within fixed time windows (e.g., 1 second).
 */
class FlowAggregator {
public:
    FlowAggregator(long long window_ms = 1000);
    ~FlowAggregator() = default;

    /**
     * @brief High-speed function to update the state of an active flow.
     * @param flow_id A unique string identifier for the flow.
     * @param packet_size The size of the current packet in bytes.
     * @param protocol The protocol number (6=TCP, 17=UDP, 1=ICMP).
     * @param current_time_ms The current timestamp in milliseconds.
     */
    void update_flow(const std::string& flow_id, int packet_size, int protocol, long long current_time_ms);

    /**
     * @brief Checks if the time window has elapsed and, if so, flushes the features.
     * @param current_time_ms The current timestamp in milliseconds.
     * @return A vector of feature vectors (one for each completed flow in the window).
     */
    std::vector<std::vector<double>> check_and_flush_window(long long current_time_ms);

private:
    std::unordered_map<std::string, FlowState> active_flows_;
    long long window_duration_ms_; 
    long long current_window_start_ms_; 

    /**
     * @brief Converts a FlowState struct into the final numerical feature vector format.
     */
    std::vector<double> extract_feature_vector(const FlowState& state, long long window_end_time_ms);
};