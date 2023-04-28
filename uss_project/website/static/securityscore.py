import tensorflow as tf
import numpy as np
import keras
import zxcvbn

def timeToCrack(password):
    return zxcvbn.zxcvbn(password)['score'] * 25

def uniqueness(password):
    Dict = {"UpperCase": 0, "LowerCase": 0, "Digits": 0, "Special": 0}
    for letter in password:
        if ord(letter) >= 65 and ord(letter) <= 90:
            Dict["UpperCase"] += 1
        elif ord(letter) >= 97 and ord(letter) <= 122:
            Dict["LowerCase"] += 1
        elif ord(letter) >= 48 and ord(letter) <= 57:
            Dict['Digits'] += 1
        else:
            Dict['Special'] += 1
    ret_score = Dict['LowerCase'] * 3 + Dict['UpperCase'] * 5 + Dict['Digits'] * 7 + Dict['Special'] * 9
    if (ret_score > 100):
        return 100
    return ret_score

train_x = np.zeros((13600, 752), dtype=np.float32)
with open('rockyou.txt', 'r', encoding='utf-8') as file:
    passwords = []
    count = 0
    for p in file:
        passwords.append(p.strip())
        counter = 0
        for letter in p:
            train_x[count][counter * 94 + (ord(letter) - 33)] = 1
            counter = counter + 1
        count = count + 1
        
training_data = []
for password in passwords:
    crack_score = 0.7 * timeToCrack(password) + 0.3 * uniqueness(password)
    training_data.append((password, crack_score))
train_y = np.array([float(score) for (_, score) in training_data]).astype(float)
sgd = tf.keras.optimizers.SGD(learning_rate = 0.1)
model = keras.Sequential()
model.add(keras.layers.Dense(64, input_shape=(752,), activation = "sigmoid"))
model.add(keras.layers.Dense(64, activation = "sigmoid"))
model.add(keras.layers.Dense(1, activation = "linear"))
model.compile(
  optimizer = sgd,
  loss = 'mse',
  metrics = ['accuracy'],
)
model.fit(train_x, train_y, epochs = 15, batch_size = 64)
model.save("pass_model.h5")