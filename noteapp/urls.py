from django.urls import path
from .views import *
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static





urlpatterns = [
    path('register/', AdminRegisterView.as_view(), name='register'),
    path('login/', AdminLoginView.as_view(), name='login'),
    
    path('adminforgot/',ForgotPasswordView.as_view()),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    path('notes/', NoteListCreateAPIView.as_view(), name='note-list-create'),
    path('notes/<int:pk>/', NoteDetailAPIView.as_view(), name='note-detail'),
    
    path('notes/search/', NoteSearchAPIView.as_view(), name='note-search'),
    
    path('todos/', TodoList.as_view(), name='todo-list'),
    path('todos/<int:pk>/', TodoDetail.as_view(), name='todo-detail'),
    
    path('groups/', GroupListCreateAPIView.as_view(), name='group-list-create'),
    path('groups/<int:pk>/', GroupDetailAPIView.as_view(), name='group-detail'),
    
    path('groups/<int:pk>/add-member/', GroupAddMemberAPIView.as_view(), name='group-add-member'),
    path('groups/<int:pk>/remove-member/', GroupRemoveMemberAPIView.as_view(), name='group-remove-member'),
    
    path('groups/<int:group_id>/tasks/', AddTaskToGroup.as_view(), name='add_task_to_group'),
    path('groups/<int:group_id>/tasks/<int:task_id>/', AddTaskToGroup.as_view(), name='update_task_in_group'),
    
    
    path('groups/<int:group_id>/add-note/', AddNoteToGroup.as_view(), name='add-note-to-group'),
    path('groups/<int:group_id>/add-note/<int:note_id>/', AddNoteToGroup.as_view(), name='update_delete_note_in_group'),
    
   
    path('api/search/', SearchAPIView.as_view(), name='search_api'),

    path('api/my-groups/', MyGroupsAPIView.as_view(), name='my_groups'),
    
    
    # path('user_notes/', UserNotes.as_view(), name='user_notes'),
    # path('groups/<int:group_id>/notes/<int:note_id>/', ShareNoteToGroup.as_view(), name='add_note_to_group'),
    # path('notes_in_group/<int:group_id>/', NotesInGroup.as_view(), name='notes_in_group'),
    
]
   
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)