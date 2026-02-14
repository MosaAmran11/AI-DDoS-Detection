#include "FlowAggregator.hpp"

// --- Implementation ---

FlowAggregator::FlowAggregator(long long window_ms) 
    : window_duration_ms_(window_ms), 
      current_window_start_ms_(std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()) {}


void FlowAggregator::update_flow(const std::string& flow_id, int packet_size, int protocol, long long current_time_ms) {
    
    // Find or create the flow state in the hash map (O(1) average time complexity)
    auto& state = active_flows_[flow_id];

    // If this is the first time we see this flow in the current map
    if (state.packet_count == 0) {
        state.flow_id = flow_id;
        state.start_time_ms = current_time_ms;
        
        // Set protocol flags
        if (protocol == 6) { state.is_tcp = true; }
        else if (protocol == 17) { state.is_udp = true; }
        else if (protocol == 1) { state.is_icmp = true; }
    }
    
    // Update the features (this runs for every packet, must be fast!)
    state.packet_count += 1;
    state.total_bytes += packet_size;
    // Track sum of squares for efficient standard deviation calculation
    state.sum_sq_pkt_size += (long long)packet_size * packet_size;
}

std::vector<double> FlowAggregator::extract_feature_vector(const FlowState& state, long long window_end_time_ms) {
    
    std::vector<double> features(FEATURE_VECTOR_SIZE, 0.0);
    
    // --- Feature Calculation (Must match feature_config.py order) ---
    
    // 0. packet_count
    double packet_count = static_cast<double>(state.packet_count);
    features[0] = packet_count; 
    
    // 1. byte_count
    double total_bytes = static_cast<double>(state.total_bytes);
    features[1] = total_bytes;
    
    // Handle division by zero for flows with zero packets
    if (packet_count == 0.0) {
        // features[2, 3] will remain 0.0, which is correct
        features[4] = 0.0; // duration_sec
        return features; 
    }
    
    // 2. avg_pkt_size
    double avg_pkt_size = total_bytes / packet_count;
    features[2] = avg_pkt_size;

    // 3. std_pkt_size (Standard Deviation of Packet Length)
    // Variance = (Sum_Sq_X - (Sum_X)^2 / N) / (N - 1)
    double variance = 0.0;
    if (packet_count > 1.0) {
        double sum_sq = static_cast<double>(state.sum_sq_pkt_size);
        double sum = total_bytes;
        variance = (sum_sq - (sum * sum) / packet_count) / (packet_count - 1.0);
    }
    features[3] = std::sqrt(std::max(0.0, variance)); // Ensure non-negative under sqrt

    // 4. duration_sec
    double duration_ms = static_cast<double>(window_end_time_ms - state.start_time_ms);
    // Convert microseconds (implicit scale) or milliseconds (explicit scale) to seconds
    // Assuming the Python flow_duration was in microseconds, but we use ms here for simplicity.
    // If your original data was in microseconds, you may need a larger scale factor here.
    double duration_sec = duration_ms / 1000.0; 
    features[4] = duration_sec;
    
    // 5. unique_src_ips
    features[5] = 1.0; // By definition of a single flow/row
    
    // 6. unique_dst_ips
    features[6] = 1.0; // By definition of a single flow/row

    // 7. tcp_count
    features[7] = state.is_tcp ? 1.0 : 0.0;
    
    // 8. udp_count
    features[8] = state.is_udp ? 1.0 : 0.0;
    
    // 9. icmp_count
    features[9] = state.is_icmp ? 1.0 : 0.0;
    
    return features;
}

std::vector<std::vector<double>> FlowAggregator::check_and_flush_window(long long current_time_ms) {
    
    // Check if the current time exceeds the window start time plus the duration
    if (current_time_ms < (current_window_start_ms_ + window_duration_ms_)) {
        // Window is not yet complete. Return empty.
        return {}; 
    }

    std::vector<std::vector<double>> window_features;
    
    // Iterate over all active flows and extract features
    for (const auto& pair : active_flows_) {
        window_features.push_back(extract_feature_vector(pair.second, current_time_ms));
    }

    // Reset for the next window:
    // 1. Clear the active flow map
    active_flows_.clear();
    // 2. Advance the window start time. Advance by the duration to keep windows contiguous.
    current_window_start_ms_ += window_duration_ms_; 
    // Handle cases where processing took too long and we missed a window. 
    // This simple approach is usually acceptable for real-time aggregation.

    // Return the aggregated features for this completed window
    return window_features;
}