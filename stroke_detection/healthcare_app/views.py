import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import CustomAuthenticationForm, CustomUserCreationForm
from django.contrib.auth.forms import UserCreationForm 
from django.contrib.auth.hashers import make_password,PBKDF2PasswordHasher
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode

def index(request): 
    return render(request, "index.html")

def login_view(request):
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('predict')  # Replace 'home' with your desired redirect URL
    else:
        form = CustomAuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logout

def signup_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password1']
            
            # Use PBKDF2PasswordHasher to hash the password
            hasher = PBKDF2PasswordHasher()
            hashed_password = make_password(password, hasher='pbkdf2_sha256')

            user = form.save(commit=False)
            user.password = hashed_password
            user.save()

            login(request, user)
            return redirect('predict')
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})


def predict(request): 
    return render(request, "predict.html") 

def result(request): 
    def pad(data):
        block_size = algorithms.AES.block_size // 8
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def encrypt_data(data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(pad(data)) + encryptor.finalize()
        return b64encode(encrypted_data).decode("utf-8")

    # Set your encryption key (16 bytes for AES-128)
    encryption_key_hex = 'b6fa44f0f7aad4dd789b03ca87fa3ec9'
    encryption_key = bytes.fromhex(encryption_key_hex)

    categorical_columns = ['gender', 'ever_married', 'work_type', 'Residence_type', 'smoking_status']

    # Load the dataset
    df = pd.read_csv("healthcare-dataset-stroke-data.csv")

    for col in categorical_columns:
        df[col] = df[col].astype(str).apply(lambda x: encrypt_data(x.encode('utf-8'), encryption_key))
    X = df.drop(['id', 'stroke'], axis=1)
    y = df["stroke"]
    X['bmi'] = X['bmi'].fillna(X['bmi'].mean())
    X['gender'] = X['gender'].astype('category')
    X['ever_married'] = X['ever_married'].astype('category')
    X['work_type'] = X['work_type'].astype('category')
    X['Residence_type'] = X['Residence_type'].astype('category')
    X['smoking_status'] = X['smoking_status'].astype('category')
    # Apply one-hot encoding
    X_encoded = pd.get_dummies(X, columns=['gender', 'ever_married', 'work_type', 'Residence_type', 'smoking_status'])

    X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.30, random_state=42)       

    sc = StandardScaler()
    x_train = pd.DataFrame(sc.fit_transform(X_train), columns=X_train.columns)
    ytrain = y_train.ravel()
    sm = SMOTE(random_state=2)
    train_x, train_y = sm.fit_resample(x_train, ytrain)

    model = DecisionTreeClassifier(criterion='entropy', random_state= 0)
    model.fit(train_x, train_y)

    user_input = {}
    user_input['gender'] = str(request.GET['n1']) 
    user_input['age'] = float(request.GET['n2']) 
    user_input['hypertension'] = float(request.GET['n3']) 
    user_input['heart_disease'] = float(request.GET['n4']) 
    user_input['ever_married'] = str(request.GET['n5']) 
    user_input['work_type'] = str(request.GET['n6']) 
    user_input['residence_type'] = str(request.GET['n7']) 
    user_input['avg_glucose_level'] = float(request.GET['n8']) 
    user_input['bmi'] = float(request.GET['n9']) 
    user_input['smoking_status'] = str(request.GET['n10']) 

    col_encrypted = [
        'TClkILD2jzKw3XLzM0KJyw==', 'TPejiaRrPlzJ4YpkFUvzHA==', 'YwbT34rtk/g7lrM930i/Tg==',
        '4yOOakKem3xlmwE41zVbbQ==', 'RlD/G8+v1TpNFYCdbJ2okQ==',
        '01xcqrc0UvHyEO1JtHnRvQ==', 'LHlIjBM+zU6j6c57mqm52A==',
        'diBaoPunqfNcFk2EWEQc5A==', 'msXb5+6uSiLRvzbNHbp4vQ==', 'uY3zhkoX+3p/84kdlFdmUg==',
        '0DAIY7SFMb+46LTiF2Z6VA==', '0upvC+TZr2kcK5qsQWRlwA==',
        'MdrfXAYa/LP4OtWyaT8Utg==', 'PbJvYp4o7egGm830iWpQEw==',
        'ckOYz1K/xdBURDNFvzhYRA==', 'nT8hfItCj2C/o7i0MqxjYg=='
    ]
    numerical_input = {'age': user_input['age'], 'hypertension':user_input['hypertension'], 'heart_disease':user_input['heart_disease'], 'avg_glucose_level':user_input['avg_glucose_level'], 'bmi':user_input['bmi']}
    categorical_input = {col: 0 for col in col_encrypted}
    combined_input = {**numerical_input, **categorical_input}

    for key, value in user_input.items():
        if key in categorical_columns:
            user_input[key] = encrypt_data(user_input[key], encryption_key)
            combined_input[user_input[key]] = 1

    all_cols = ['age', 'hypertension', 'heart_disease', 'avg_glucose_level', 'bmi'] + col_encrypted

    data_to_predict = []
    for i in range(0,  len(all_cols)):
        data_to_predict.append(combined_input[all_cols[i]])

    columns = ['age', 'hypertension', 'heart_disease', 'avg_glucose_level', 'bmi',
            'gender_TClkILD2jzKw3XLzM0KJyw==', 'gender_TPejiaRrPlzJ4YpkFUvzHA==',
            'gender_YwbT34rtk/g7lrM930i/Tg==',
            'ever_married_4yOOakKem3xlmwE41zVbbQ==',
            'ever_married_RlD/G8+v1TpNFYCdbJ2okQ==',
            'work_type_01xcqrc0UvHyEO1JtHnRvQ==',
            'work_type_LHlIjBM+zU6j6c57mqm52A==',
            'work_type_diBaoPunqfNcFk2EWEQc5A==',
            'work_type_msXb5+6uSiLRvzbNHbp4vQ==',
            'work_type_uY3zhkoX+3p/84kdlFdmUg==',
            'Residence_type_0DAIY7SFMb+46LTiF2Z6VA==',
            'Residence_type_0upvC+TZr2kcK5qsQWRlwA==',
            'smoking_status_MdrfXAYa/LP4OtWyaT8Utg==',
            'smoking_status_PbJvYp4o7egGm830iWpQEw==',
            'smoking_status_ckOYz1K/xdBURDNFvzhYRA==',
            'smoking_status_nT8hfItCj2C/o7i0MqxjYg==']

    final_data_to_predict = pd.DataFrame([data_to_predict], columns=columns)
    pred = model.predict(final_data_to_predict)

    result1 = "" 
    if pred == [1]: 
        result1 = "You have chances of getting a stroke in the future. Please consult a neurologist!"
    else: 
        result1 = "You have no chance of getting a stroke."

    return render(request, "predict.html", {"result2": result1})