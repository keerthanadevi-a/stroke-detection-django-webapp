import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import CustomAuthenticationForm, CustomUserCreationForm
from django.contrib.auth.forms import UserCreationForm 
from django.contrib.auth.hashers import make_password

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
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()

            login(request, user)
            return redirect('predict')
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})


def predict(request): 
    return render(request, "predict.html") 

def result(request): 
    stroke_data = pd.read_csv("healthcare-dataset-stroke-data.csv")
    X = stroke_data.drop(['id', 'stroke'], axis=1)
    y = stroke_data["stroke"]
    X['bmi'] = X['bmi'].fillna(X['bmi'].mean())
    X['gender'] = X['gender'].astype('category')
    X['ever_married'] = X['ever_married'].astype('category')
    X['work_type'] = X['work_type'].astype('category')
    X['Residence_type'] = X['Residence_type'].astype('category')
    X['smoking_status'] = X['smoking_status'].astype('category')
    categories = {}
    categories['gender'] = list(X['gender'].cat.categories)
    categories['ever_married'] = list(X['ever_married'].cat.categories)
    categories['work_type'] = list(X['work_type'].cat.categories)
    categories['Residence_type'] = list(X['Residence_type'].cat.categories)
    categories['smoking_status'] = list(X['smoking_status'].cat.categories)
    X['gender'] = X['gender'].cat.codes
    X['ever_married'] = X['ever_married'].cat.codes
    X['work_type'] = X['work_type'].cat.codes
    X['Residence_type'] = X['Residence_type'].cat.codes
    X['smoking_status'] = X['smoking_status'].cat.codes

    model = RandomForestClassifier(criterion='entropy', n_estimators=150, random_state=0)
    model.fit(X, y)        

    gender = float(request.GET['n1']) 
    age = float(request.GET['n2']) 
    hypertension = float(request.GET['n3']) 
    heart_disease = float(request.GET['n4']) 
    ever_married = float(request.GET['n5']) 
    work_type = float(request.GET['n6']) 
    residence_type = float(request.GET['n7']) 
    avg_glucose_level = float(request.GET['n8']) 
    bmi = float(request.GET['n9']) 
    smoking_status = float(request.GET['n10']) 

    pred = model.predict([[gender, age, hypertension, 
                        heart_disease, ever_married, work_type, residence_type, avg_glucose_level, bmi, smoking_status]]) 

    result1 = "" 
    if pred == [0]: 
        result1 = "You have chances of getting stroke in the future. Please consult a neurologist!"
    else: 
        result1 = "You don't have a stroke."

    return render(request, "predict.html", {"result2": result1})