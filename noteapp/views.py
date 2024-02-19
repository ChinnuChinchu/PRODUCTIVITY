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
                return Response({'msg': 'logged in successfully', 'token': token.key})
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
    

############################# GROUP #########################

class GroupListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        groups = Group.objects.all()
        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = GroupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

####################### MEMBER #######################

class MembershipListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        memberships = Membership.objects.all()
        serializer = MembershipSerializer(memberships, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = MembershipSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

############################ TASK ############################
class TaskListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Task.objects.filter(created_by=self.request.user)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class TaskDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Task.objects.get(pk=pk)
        except Task.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        task = self.get_object(pk)
        serializer = TaskSerializer(task)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        task = self.get_object(pk)
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        task = self.get_object(pk)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

######################## SEARCH ######################
    
class NoteSearchAPIView(generics.ListAPIView):
    queryset = Note.objects.all()
    serializer_class = NoteSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['title']
    
    
##################### Todo ##########################    
    
class TodoDetailAPIView(APIView):
    def get_object(self, pk):
        return get_object_or_404(Todo, pk=pk)

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

class TodoListAPIView(APIView):
    def get(self, request):
        todos = Todo.objects.all()
        serializer = TodoSerializer(todos, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = TodoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)