import cv2
import mediapipe as mp
import math
import time
import requests

mp_pose = mp.solutions.pose
pose = mp_pose.Pose()

cap = cv2.VideoCapture(0)
bad_posture_count = 0
start_bad_time = None

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    image_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    results = pose.process(image_rgb)

    if results.pose_landmarks:
        l = results.pose_landmarks.landmark[mp_pose.PoseLandmark.LEFT_SHOULDER]
        r = results.pose_landmarks.landmark[mp_pose.PoseLandmark.RIGHT_SHOULDER]

        dx = l.x - r.x
        dy = l.y - r.y
        angle = math.degrees(math.atan2(dy, dx))

        # 기준 각도 초과 → 일정 시간 이상 유지 시 count++
        if abs(angle) > 10:
            if start_bad_time is None:
                start_bad_time = time.time()
            elif time.time() - start_bad_time > 3:
                bad_posture_count += 1
                print(f"⚠ 자세 나쁨 count 증가 → {bad_posture_count}")
                start_bad_time = None
        else:
            start_bad_time = None

    cv2.imshow("Pose Check", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()

# Django API로 count 전송
response = requests.post(
    "http://127.0.0.1:8000/api/posture/",
    json={"count": bad_posture_count}
)
print("✅ 서버 응답:", response.json())
