from django.urls import path
from .views import *
from django.contrib.auth import views as auth_views




urlpatterns = [
    path('register/', AdminRegisterView.as_view(), name='register'),
    path('login/', AdminLoginView.as_view(), name='login'),
    path('adminforgot/',ForgotPasswordView.as_view()),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('notes/', NoteListCreateAPIView.as_view(), name='note-list-create'),
    path('notes/<int:pk>/', NoteDetailAPIView.as_view(), name='note-detail'),
    path('groups/', GroupListCreateAPIView.as_view(), name='group-list-create'),
    path('memberships/', MembershipListCreateAPIView.as_view(), name='membership-list-create'),
    path('tasks/', TaskListCreateAPIView.as_view(), name='task-list-create'),
    path('tasks/<int:pk>/', TaskDetailAPIView.as_view(), name='task-detail'),
    path('notes/search/', NoteSearchAPIView.as_view(), name='note-search'),
    path('todos/', TodoListAPIView.as_view(), name='todo-list'),
    path('todos/<int:pk>/', TodoDetailAPIView.as_view(), name='todo-detail'),
   
]