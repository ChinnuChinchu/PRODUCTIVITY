from django.shortcuts import render

# Create your views here.
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import PasswordResetForm
from django.core.mail import send_mail
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from django.contrib.auth.models import User


from rest_framework.views import APIView
from .models import *
from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.decorators import permission_classes,authentication_classes
from rest_framework.permissions import AllowAny
import random
import string
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.models import Session
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.http import Http404 
from rest_framework import filters
from rest_framework.exceptions import PermissionDenied



class AdminRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        a = adminserializer(data=request.data)
        if a.is_valid():
            a.save()
            return Response({'msg': "Registered successfully", 'data': a.data}, status=status.HTTP_201_CREATED)
        else:
            return Response(a.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        qs = User.objects.all()
        a = adminserializer(qs, many=True)
        return Response(a.data)



class AdminLoginView(APIView):
    def post(self, request):
        serializer = loginserializer(data=request.data)
        
        if serializer.is_valid():
            uname = serializer.validated_data.get("username")
            password = serializer.validated_data.get("password")
            
            user = authenticate(request, username=uname, password=password)
            
            if user:
                login(request, user)
                # Generate or retrieve the token for the user
                token, created = Token.objects.get_or_create(user=user)
                return Response({'msg': 'logged in successfully', 'token': token.key,'user_id': user.id})
            else:
                return Response({'msg': 'login failed'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class ForgotPasswordView(APIView):
    def post(self, request):
        username = request.data.get('username')
        try:
            user = User.objects.get(username=username)

            # Generate a new password
            new_password = generate_random_otp()

            # Update the user's password in the database
            user.password = make_password(new_password)
            user.save()

            # Send the new password to the user's email
            self.send_new_password_to_user_email(user, new_password)

            return Response({'msg': 'New password sent successfully'})
        except ObjectDoesNotExist:
            return Response({'msg': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Helper function to send the new password to the user's email
    def send_new_password_to_user_email(self, user, new_password):
        subject = 'New Password'
        message = f'Your new password is: {new_password}'
        from_email = 'chinchuofficialweb@gmail.com'  # Update with your email
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)


def generate_random_otp():
    return ''.join(random.choices(string.digits, k=6))



class ResetPasswordView(APIView):
    def post(self, request):
        username = request.data.get('username')
        new_password = request.data.get('new_password')

        if not username or not new_password:
            return Response({'msg': 'Invalid data provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)

            # Reset password
            user.password = make_password(new_password)
            user.save()

            return Response({'msg': 'Password reset successfully'})
        except ObjectDoesNotExist:
            return Response({'msg': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        
        
############################ NOTE ########################

class NoteListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
      
        return Note.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class NoteDetailAPIView(APIView):
    def get_object(self, pk):
        try:
            return Note.objects.get(pk=pk)
        except Note.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        note = self.get_object(pk)
        serializer = NoteSerializer(note)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        note = self.get_object(pk)
        serializer = NoteSerializer(note, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        note = self.get_object(pk)
        note.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


######################## SEARCH ######################
    
class NoteSearchAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        title = request.data.get('title', None)
        if title is not None:
            notes = Note.objects.filter(title__icontains=title)
            todos = Todo.objects.filter(title__icontains=title)
            note_serializer = NoteSerializer(notes, many=True)
            todo_serializer = TodoSerializer(todos, many=True)
            response_data = {
                "notes": note_serializer.data,
                "todos": todo_serializer.data
            }
            return Response(response_data)
        else:
            return Response({"error": "Title parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    
##################### Todo ##########################    

class TodoList(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        todos = Todo.objects.filter(owner=request.user)
        serializer = TodoSerializer(todos, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = TodoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TodoDetail(APIView):
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk):
        try:
            return Todo.objects.get(pk=pk, owner=self.request.user)
        except Todo.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        todo = self.get_object(pk)
        serializer = TodoSerializer(todo)
        return Response(serializer.data)

    def put(self, request, pk):
        todo = self.get_object(pk)
        serializer = TodoSerializer(todo, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        todo = self.get_object(pk)
        todo.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
################# Group ####################

class GroupListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        groups = NewGroup.objects.filter(owner=request.user)
        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = GroupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        
class GroupDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        return get_object_or_404(NewGroup, pk=pk)

    def get(self, request, pk):
        group = self.get_object(pk)
        serializer = GroupSerializer(group)
        return Response(serializer.data)

    def put(self, request, pk):
        group = self.get_object(pk)
        serializer = GroupSerializer(group, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        group = self.get_object(pk)
        group.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    


class GroupAddMemberAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_registered_users_emails(self, group):
        group_members_emails = group.members.values_list('email', flat=True)
        owner_email = group.owner.email
        return User.objects.exclude(email__in=group_members_emails).exclude(email=owner_email).values_list('email', flat=True)

    def get(self, request, pk):
        group = get_object_or_404(NewGroup, pk=pk)
        registered_users_emails = self.get_registered_users_emails(group)
        owner_details = {
            'username': group.owner.username,
            'email': group.owner.email,
            # Add more owner details as needed
        }
        member_count = group.members.count()
        return Response({'registered_users_emails': registered_users_emails, 'owner_details': owner_details, 'member_count': member_count}, status=status.HTTP_200_OK)

    def put(self, request, pk):
        group = get_object_or_404(NewGroup, pk=pk)
        if 'email' not in request.data:
            return Response({'email': 'This field is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=request.data['email'])
            group.members.add(user)
            registered_users_emails = self.get_registered_users_emails(group)
            serializer = GroupSerializer(group)
            owner_details = {
                'username': group.owner.username,
                'email': group.owner.email,
                # Add more owner details as needed
            }
            member_count = group.members.count()
            # added_member_email=group.members.values_list('email', flat=True) 
            return Response({'registered_users_emails': registered_users_emails, 'group': serializer.data, 'owner_details': owner_details, 'member_count': member_count}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        
class GroupRemoveMemberAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        group = get_object_or_404(NewGroup, pk=pk)
        serializer = GroupSerializer(group)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        group = get_object_or_404(NewGroup, pk=pk)
        if 'email' not in request.data:
            return Response({'email': 'This field is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=request.data['email'])
            if user in group.members.all():
                group.members.remove(user)
                return Response({'detail': 'Member removed successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'User is not a member of the group'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        
########################## ADD A NEW TASK TO THE GROUP #########################

class AddTaskToGroup(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, group_id):
        group = get_object_or_404(NewGroup, id=group_id)
        tasks = Task.objects.filter(group=group)
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

    def post(self, request, group_id):
        group = get_object_or_404(NewGroup, id=group_id)
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user, group=group)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, group_id, task_id):
        task = get_object_or_404(Task, id=task_id)
        if request.user != task.created_by:
            raise PermissionDenied("You do not have permission to update this task.")
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, group_id, task_id):
        task = get_object_or_404(Task, id=task_id)
        if request.user != task.created_by:
            raise PermissionDenied("You do not have permission to delete this task.")
        task.delete()
        message = "Task deleted successfully."

        return Response({"message": message},status=status.HTTP_204_NO_CONTENT)


############################## ADD A NEW NOTE TO THE GROUP ################################
class AddNoteToGroup(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, group_id):
        group = get_object_or_404(NewGroup, id=group_id)
        notes = GroupNote.objects.filter(newgroup=group)
        serializer = AddNoteSerializerGroup(notes, many=True)
        return Response(serializer.data)

    def post(self, request, group_id):
        group = get_object_or_404(NewGroup, id=group_id)
        serializer = AddNoteSerializerGroup(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user, newgroup=group)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, group_id, note_id):
        note = get_object_or_404(GroupNote, id=note_id)
        if request.user != note.owner:
            raise PermissionDenied("You do not have permission to update this note.")
        serializer = AddNoteSerializerGroup(note, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, group_id, note_id):
        note = get_object_or_404(GroupNote, id=note_id)
        if request.user != note.owner:
            raise PermissionDenied("You do not have permission to delete this note.")
        note.delete()
        message = "Note deleted successfully."
        return Response({"message": message}, status=status.HTTP_204_NO_CONTENT)


######################### All in One Search #############################

class SearchAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        query = request.data.get('query', None)
        if query is None:
            return Response({"error": "Query parameter 'query' is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        notes = Note.objects.filter(title__icontains=query) | Note.objects.filter(content__icontains=query)
        tasks = Task.objects.filter(title__icontains=query) | Task.objects.filter(content__icontains=query)
        todos = Todo.objects.filter(title__icontains=query) | Todo.objects.filter(description__icontains=query)
        groupnotes = GroupNote.objects.filter(g_title__icontains=query) | GroupNote.objects.filter(content__icontains=query)
        
        note_serializer = NoteSerializer(notes, many=True)
        task_serializer = TaskSerializer(tasks, many=True)
        todo_serializer = TodoSerializer(todos, many=True)
        groupnote_serializer = GroupSerializer(groupnotes, many=True)
        
        response_data = {
            "notes": note_serializer.data,
            "tasks": task_serializer.data,
            "todos": todo_serializer.data,
            "groupnotes":groupnote_serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)


####################### The list of groups ##################

class MyGroupsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        created_groups = NewGroup.objects.filter(owner=user)
        added_groups = NewGroup.objects.filter(members=user)
        
        created_serializer = GroupSerializer(created_groups, many=True)
        added_serializer = GroupSerializer(added_groups, many=True)
        
        owner_serializer = UserSerializer(user)
        
        return Response({
            'owner_details': owner_serializer.data,
            'created_groups': created_serializer.data,
            'added_groups': added_serializer.data
        }, status=status.HTTP_200_OK)



















































    
    
# ############################### SHARE NOTES TO THE GROUP ####################################
    
# class UserNotes(APIView):
#     permission_classes = [IsAuthenticated]
#     def get(self, request):
#         # Fetch notes of the current logged-in user
#         user_notes = Note.objects.filter(owner=request.user)
#         serializer = NoteSerializer(user_notes, many=True)
#         return Response(serializer.data)

 

# class ShareNoteToGroup(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request, group_id, note_id):
#         # Check if the group exists
#         try:
#             group = NewGroup.objects.get(id=group_id)
#         except NewGroup.DoesNotExist:
#             return Response({"message": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        
#         # Check if the user making the request is a member of the group
#         if request.user not in group.members.all():
#             return Response({"message": "You are not a member of this group"}, status=status.HTTP_403_FORBIDDEN)

#         # Check if the note exists and belongs to the user
#         try:
#             note = Note.objects.get(id=note_id, owner=request.user)
#         except Note.DoesNotExist:
#             return Response({"message": "Note not found or does not belong to you"}, status=status.HTTP_404_NOT_FOUND)

#         # Add the note to the group
#         note.group = group
#         note.save()
        
#         serializer = NoteSerializer(note)

#         return Response({"message": "Note added to group successfully", "note": serializer.data}, status=status.HTTP_200_OK)

#     def delete(self, request, group_id, note_id):
#         # Check if the group exists
#         try:
#             group = NewGroup.objects.get(id=group_id)
#         except NewGroup.DoesNotExist:
#             return Response({"message": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        
#         # Check if the user making the request is a member of the group
#         if request.user not in group.members.all():
#             return Response({"message": "You are not a member of this group"}, status=status.HTTP_403_FORBIDDEN)

#         # Check if the note exists, belongs to the user, and is in the group
#         try:
#             note = Note.objects.get(id=note_id, owner=request.user, group=group)
#         except Note.DoesNotExist:
#             return Response({"message": "Note not found or does not belong to you"}, status=status.HTTP_404_NOT_FOUND)

#         # Delete the note from the group
#         note.group = None
#         note.save()

#         return Response({"message": "Note removed from group successfully"}, status=status.HTTP_200_OK)
    
    
    
# class NotesInGroup(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request, group_id):
#         # Check if the group exists
#         try:
#             group = NewGroup.objects.get(id=group_id)
#         except NewGroup.DoesNotExist:
#             return Response({"message": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        
#         # Check if the user making the request is a member of the group
#         if request.user not in group.members.all():
#             return Response({"message": "You are not a member of this group"}, status=status.HTTP_403_FORBIDDEN)

#         # Get all notes in the group
#         group_notes = Note.objects.filter(group=group)
#         serializer = NoteSerializer(group_notes, many=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)


