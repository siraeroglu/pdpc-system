# People Detection and Counting System

A real-time web-based platform that detects and counts people in images, videos, and live camera streams using the latest deep learning YOLOv8 architecture with GPU-accelerated OpenCV pipelines.  
It is designed for **corporate** and **individual** use, enabling occupancy analytics, crowd monitoring, and automation triggers for smart environments.

---

## Key Features
- **Real-Time Detection:** Achieves <200ms inference latency even on standard hardware.
- **Multiple Input Modes:** 
  - Live detection from USB webcams, laptop cameras, and RTSP IP cameras (up to 30 FPS)
  - Upload photos (.jpeg, .png) and videos (.mp4, .mov) up to 1GB
- **User Roles:** 
  - **Trial User:** Limited daily uploads (1 photo & 1 video per day)
  - **Premium User:** Unlimited uploads and real-time detection (monthly subscription)
- **Output Data:** Annotated frames and JSON-based summaries for seamless dashboard and mobile integration.
- **Use Cases:** 
  - Library occupancy rate monitoring
  - Subway and public transport crowd analytics
  - Public restroom, hall, and event space usage tracking
  - Smart building automation triggers (e.g., emergency lighting, HVAC)

---

## Technology Stack
- **Backend:** Python (Flask), Flask-Login, Flask-Mail, Werkzeug  
- **Frontend:** HTML, CSS, JavaScript  
- **Detection Framework:** YOLOv8 (Ultralytics), OpenCV  
- **Database:** PostgreSQL, DBeaver  
- **Infrastructure:** Docker, DigitalOcean (Production)  
- **Version Control:** Git & GitHub  

---

## Workflow Highlights
- **User Management:** Registration, login, and profile editing with premium request handling.
- **Media Upload & Processing:** Users can upload photos or videos; detection pipeline returns annotated frames and counts.
- **Live Detection:** Supports both USB and IP cameras with real-time inference and visual feedback.
- **Report Generation:** Users can view and export occupancy analytics.
- **Security:** Email-based authentication and session management.

---

## Example Applications
- Real-time monitoring of subway stations and libraries
- Automated reporting of restroom occupancy
- Fast, low-cost crowd analytics for events and emergency planning
- Drone-based aerial counting for industrial and agricultural use cases

---

## Algorithms (Simplified)
- **User Authentication:** Secure registration and login system with email and password validation.
- **Detection Pipeline:** YOLOv8 for human detection, OpenCV for video feed handling, and optimized data pipelines for low latency.
- **User Limits & Premium Mode:** Daily upload limits for trial users; unlimited access for premium subscribers.
- **Report Generation:** Aggregated occupancy data and visualizations.

---

## Getting Started
1. Clone this repository:
    ```bash
   git clone https://github.com/<siraeroglu>/people-detection-counting-system.git

2. Install dependencies:
   ```bash
   pip install -r requirements.txt

3. Run the application:
    ```bash
   python app.py
