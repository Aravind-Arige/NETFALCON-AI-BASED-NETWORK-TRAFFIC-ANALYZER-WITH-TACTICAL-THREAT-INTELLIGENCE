import os
from alerts.dispatcher import AlertDispatcher

def main():
    print("Testing Alert System...")
    
    # 1. Initialize the dispatcher
    dispatcher = AlertDispatcher()
    
    # 2. Mock a high-severity anomaly result
    mock_anomaly = {
        "label": "critical",
        "score": 95,
        "explanations": [
            {"description": "Massive UDP Flood detected", "percent_diff": 450},
            {"description": "Unusual number of active flows", "percent_diff": 200}
        ],
        "suggested_actions": ["Investigate source IPs immediately", "Block UDP traffic on affected ports"]
    }
    
    # 3. Mock raw metrics
    mock_metrics = {
        "bandwidth_in": 150000.5,
        "bandwidth_out": 200.0,
        "packet_loss": 5.2,
        "active_flows": 1500
    }
    
    # 4. Dispatch the alert
    # We call dispatcher.dispatch directly. It will run in a separate thread.
    dispatcher.dispatch(mock_anomaly, mock_metrics)
    
    # Wait a few seconds for daemon thread to send the email
    import time
    time.sleep(5)
    print("Test completed. Check your console output and email inbox.")

if __name__ == "__main__":
    main()
