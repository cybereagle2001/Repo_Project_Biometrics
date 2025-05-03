import os
import pickle
import hashlib
import cv2
import numpy as np
import sys
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from enhance import image_enhance
from skimage.morphology import skeletonize
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def removedot(invertThin):
    temp0 = np.array(invertThin[:])
    temp1 = temp0 / 255
    temp2 = np.array(temp1)
    temp3 = np.array(temp2)
    enhanced_img = np.array(temp0)
    filter0 = np.zeros((10, 10))
    W, H = temp0.shape[:2]
    filtersize = 6
    
    for i in range(W - filtersize):
        for j in range(H - filtersize):
            filter0 = temp1[i:i + filtersize, j:j + filtersize]
            flag = sum(filter0[:, 0]) == 0 + sum(filter0[:, filtersize - 1]) == 0 + sum(filter0[0, :]) == 0 + sum(filter0[filtersize - 1, :]) == 0
            if flag > 3:
                temp2[i:i + filtersize, j:j + filtersize] = np.zeros((filtersize, filtersize))
    return temp2

def get_descriptors(img):
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    img = clahe.apply(img)
    img = image_enhance.image_enhance(img)
    img = np.array(img, dtype=np.uint8)
    ret, img = cv2.threshold(img, 127, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)
    img[img == 255] = 1
    skeleton = skeletonize(img)
    skeleton = np.array(skeleton, dtype=np.uint8)
    skeleton = removedot(skeleton)
    harris_corners = cv2.cornerHarris(img, 3, 3, 0.04)
    harris_normalized = cv2.normalize(harris_corners, 0, 255, norm_type=cv2.NORM_MINMAX, dtype=cv2.CV_32FC1)
    threshold_harris = 125
    keypoints = [cv2.KeyPoint(y, x, 1) for x in range(harris_normalized.shape[0]) for y in range(harris_normalized.shape[1]) if harris_normalized[x][y] > threshold_harris]
    orb = cv2.ORB_create()
    _, des = orb.compute(img, keypoints)
    return keypoints, des

def enroll_fingerprint(image_path, user_id, db_path="fingerprint_database.pkl"):
    """
    Enrolls a fingerprint by extracting its ORB descriptors and storing them in a database.

    Parameters:
        image_path (str): Path to the fingerprint image.
        user_id (str): Unique identifier for the user (e.g., "Alice").
        db_path (str): Path to the database file.
    """
    # Load image
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        print(f"Error loading image: {image_path}")
        return

    # Get keypoints and descriptors
    kp, des = get_descriptors(img)

    if des is None or len(kp) == 0:
        print("No descriptors found in the image.")
        return

    # Load existing database or initialize new one
    db = {}
    if os.path.exists(db_path):
        with open(db_path, 'rb') as f:
            try:
                db = pickle.load(f)
            except EOFError:
                print("Database file is empty or corrupted.")

    # Store descriptor and keypoints under user_id
    db[user_id] = {
        'keypoints': kp,
        'descriptors': des
    }

    # Save updated database
    with open(db_path, 'wb') as f:
        pickle.dump(db, f)

    print(f"Fingerprint enrolled successfully for user '{user_id}'.")

def verify_fingerprint(fingerprint_path, database_path="database"):
    img1 = cv2.imread(fingerprint_path, cv2.IMREAD_GRAYSCALE)
    kp1, des1 = get_descriptors(img1)
    
    for db_fingerprint in os.listdir(database_path):
        img2 = cv2.imread(os.path.join(database_path, db_fingerprint), cv2.IMREAD_GRAYSCALE)
        kp2, des2 = get_descriptors(img2)
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = sorted(bf.match(des1, des2), key=lambda match: match.distance)
        
        if matches and sum(match.distance for match in matches) / len(matches) < 33:
            print(f"Fingerprint matches: {db_fingerprint}")
            
            img4 = cv2.drawKeypoints(img1, kp1, outImage=None)
            img5 = cv2.drawKeypoints(img2, kp2, outImage=None)
            f, axarr = plt.subplots(1,2)
            axarr[0].imshow(img4, cmap='gray')
            axarr[1].imshow(img5, cmap='gray')
            plt.suptitle("POSSIBLE MATCH", fontsize=16, fontweight='bold')
            plt.show()
            
            img3 = cv2.drawMatches(img1, kp1, img2, kp2, matches, None, flags=2)
            img_height, img_width, _ = img3.shape
            plt.imshow(img3)
            plt.axis("off")
            
            fig, ax = plt.gca(), plt.gca()
            width, height = 150, 40
            x = (img_width - width) // 2
            y = 280
            rect = patches.Rectangle((x, y), width, height, linewidth=2, edgecolor='green', facecolor='white', alpha=0.3)
            ax.add_patch(rect)
            plt.text(x + 10, y + 25, "MATCHED", fontsize=14, fontweight="bold", color="green")
            plt.suptitle("MATCHED " + db_fingerprint, fontsize=16, fontweight='bold')
            plt.show()
            
            return True
    
    print("Fingerprint does not match.")
    return False

def derive_key(fingerprint_path, salt=b"somesalt", iterations=100000):
    _, descriptors = get_descriptors(cv2.imread(fingerprint_path, cv2.IMREAD_GRAYSCALE))
    fingerprint_hash = hashlib.sha256(descriptors.tobytes()).digest()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    return kdf.derive(fingerprint_hash)

def encrypt_file(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length
    with open(file_path + ".enc", 'wb') as f:
        f.write(iv + cipher.update(plaintext) + cipher.finalize())
    print("Fichier chiffré avec succès.")

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as f:
        iv, ciphertext = f.read(16), f.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    plaintext = cipher.update(ciphertext) + cipher.finalize()
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    with open(encrypted_file_path.replace(".enc", ""), 'wb') as f:
        f.write(plaintext)
    print("Fichier déchiffré avec succès.")

def verify_fingerprint_only(fingerprint_path):
    """
    Verify the fingerprint without performing any file operations.
    """
    img1 = cv2.imread(fingerprint_path, cv2.IMREAD_GRAYSCALE)
    kp1, des1 = get_descriptors(img1)

    for db_fingerprint in os.listdir("database"):
        img2 = cv2.imread(os.path.join("database", db_fingerprint), cv2.IMREAD_GRAYSCALE)
        kp2, des2 = get_descriptors(img2)
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = sorted(bf.match(des1, des2), key=lambda match: match.distance)

        if matches and sum(match.distance for match in matches) / len(matches) < 33:
            print(f"Fingerprint matches: {db_fingerprint}")
            return True

    print("Fingerprint does not match.")
    return False

def biometric_authenticate(fingerprint_path, operation, file_path):
    if verify_fingerprint_only(fingerprint_path):
        key = derive_key(fingerprint_path)
        if operation == "encrypt":
            encrypt_file(file_path, key)
        elif operation == "decrypt":
            decrypt_file(file_path, key)
        else:
            print("Invalid operation. Use 'encrypt' or 'decrypt'.")
    else:
        print("Authentication failed. Fingerprint not recognized.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <empreinte.png> <encrypt|decrypt> <fichier>")
        sys.exit(1)
    biometric_authenticate(sys.argv[1], sys.argv[2], sys.argv[3])

