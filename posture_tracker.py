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

def is_bad_posture(landmarks):
    # 어깨 기울기 계산
    l_shoulder = landmarks[mp_pose.PoseLandmark.LEFT_SHOULDER]
    r_shoulder = landmarks[mp_pose.PoseLandmark.RIGHT_SHOULDER]
    dx = l_shoulder.x - r_shoulder.x
    dy = l_shoulder.y - r_shoulder.y
    shoulder_angle = math.degrees(math.atan2(dy, dx))

    # 고개 좌우 기울기 계산 (귀 기준)
    l_ear = landmarks[mp_pose.PoseLandmark.LEFT_EAR]
    r_ear = landmarks[mp_pose.PoseLandmark.RIGHT_EAR]
    ear_angle = math.degrees(math.atan2(l_ear.y - r_ear.y, l_ear.x - r_ear.x))

    # 고개 숙임 판단 (코와 어깨 높이 비교)
    nose = landmarks[mp_pose.PoseLandmark.NOSE]
    shoulder_avg_y = (l_shoulder.y + r_shoulder.y) / 2
    head_down = nose.y > shoulder_avg_y + 0.1

    return abs(shoulder_angle) > 10 or abs(ear_angle) > 10 or head_down

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    image_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    results = pose.process(image_rgb)

    if results.pose_landmarks:
        landmarks = results.pose_landmarks.landmark

        if is_bad_posture(landmarks):
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
    "http://127.0.0.1:8000/api/analyze/",
    json={"posture_count": bad_posture_count}
)
print("✅ Claude 분석 결과:")
print(response.json())
