# myapp/serializers.py
from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User


class adminserializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['username','email','password']

    def create(self,validated_data):
        a=User.objects.create(username=validated_data['username'],email=validated_data['email'])
        a.set_password(validated_data['password'])
        a.save()
        return a
        
class loginserializer(serializers.Serializer):
    username=serializers.CharField(max_length=30)
    password=serializers.CharField(max_length=30)
        

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields=['id','title','content','categorize_note','created_at','updated_at','favorite']
        read_only_fields=['owner']


        
class AddNoteSerializerGroup(serializers.ModelSerializer):
    class Meta:
        model=GroupNote
        fields=['id','g_title','content','created_at','updated_at','favorite','owner']
        read_only_fields=['owner']

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id','title','content','due_date','created_by']

class TodoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Todo
        fields = '__all__'
         
    
class GroupSerializer(serializers.ModelSerializer):
    
    members_email = serializers.SerializerMethodField()

    class Meta:
        model = NewGroup
        fields = ('id', 'owner', 'group_name', 'group_image', 'description','created_at','members_email')
        
    def get_members_email(self, obj):
        user_ids = obj.members.all().values_list('id', flat=True)
        email = User.objects.filter(id__in=user_ids).values_list('email', flat=True)
        return email
    
    
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')


        
        

        
        
