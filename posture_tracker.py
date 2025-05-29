import cv2
import mediapipe as mp
import math
import time
import requests

mp_pose = mp.solutions.pose
mp_face_mesh = mp.solutions.face_mesh
pose = mp_pose.Pose()
face_mesh = mp_face_mesh.FaceMesh(static_image_mode=False, max_num_faces=1, refine_landmarks=True)

cap = cv2.VideoCapture(0)
bad_posture_count = 0
start_bad_time = None

def is_bad_posture(pose_landmarks, face_landmarks):
    # --- 어깨 기울기 ---
    l_shoulder = pose_landmarks[mp_pose.PoseLandmark.LEFT_SHOULDER]
    r_shoulder = pose_landmarks[mp_pose.PoseLandmark.RIGHT_SHOULDER]
    dx = l_shoulder.x - r_shoulder.x
    dy = l_shoulder.y - r_shoulder.y
    shoulder_angle = math.degrees(math.atan2(dy, dx))

    # --- 고개 좌우 기울기 ---
    l_ear = pose_landmarks[mp_pose.PoseLandmark.LEFT_EAR]
    r_ear = pose_landmarks[mp_pose.PoseLandmark.RIGHT_EAR]
    ear_angle = math.degrees(math.atan2(l_ear.y - r_ear.y, l_ear.x - r_ear.x))

    # --- 고개 숙임 ---
    nose = pose_landmarks[mp_pose.PoseLandmark.NOSE]
    shoulder_avg_y = (l_shoulder.y + r_shoulder.y) / 2
    head_down = nose.y > shoulder_avg_y + 0.1

    # --- 시선 흐트러짐 (왼쪽/오른쪽) ---
    gaze_off = False
    if face_landmarks:
        # 홍채 중심: 468 (왼쪽), 473 (오른쪽)
        # 눈 경계: 33, 133 (왼쪽 눈), 362, 263 (오른쪽 눈)
        left_iris = face_landmarks.landmark[468]
        left_eye_left = face_landmarks.landmark[33]
        left_eye_right = face_landmarks.landmark[133]

        # 눈동자 좌/우 상대 위치 계산 (정규화)
        eye_range = left_eye_right.x - left_eye_left.x
        iris_pos = (left_iris.x - left_eye_left.x) / eye_range if eye_range > 0 else 0.5

        # 0.4~0.6이 정면으로 보고 있는 기준
        if iris_pos < 0.35 or iris_pos > 0.65:
            gaze_off = True

    return abs(shoulder_angle) > 10 or abs(ear_angle) > 10 or head_down or gaze_off

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    image_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    pose_results = pose.process(image_rgb)
    face_results = face_mesh.process(image_rgb)

    if pose_results.pose_landmarks:
        pose_landmarks = pose_results.pose_landmarks.landmark
        face_landmarks = face_results.multi_face_landmarks[0] if face_results.multi_face_landmarks else None

        if is_bad_posture(pose_landmarks, face_landmarks):
            if start_bad_time is None:
                start_bad_time = time.time()
            elif time.time() - start_bad_time > 3:
                bad_posture_count += 1
                print(f"⚠ 자세 나쁨 count 증가 → {bad_posture_count}")
                start_bad_time = None
        else:
            start_bad_time = None

    cv2.imshow("Posture & Gaze Tracker", frame)
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
