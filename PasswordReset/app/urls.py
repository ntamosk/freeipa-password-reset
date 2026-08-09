from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('gettoken/', views.GetToken.as_view(), name='gettoken'),
    path('setpassword/', views.SetPassword.as_view(), name='set_password'),
    path('change/', views.ChangePassword.as_view(), name='change_password'),
]
