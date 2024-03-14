# from datetime import timezone
from django.db import models
from django.utils import timezone


# Create your models here.

from django.contrib.auth.models import User

class Note(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    categorize_note=models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    favorite=models.BooleanField(default=False)
    
     

       
class NewGroup(models.Model):   
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    group_name = models.CharField(max_length=100)
    group_image = models.ImageField(upload_to='group_images/', null=True, blank=True)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    members = models.ManyToManyField(User, related_name='newgroups', blank=True)
   

    def __str__(self):
        return self.group_name   


class Task(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    group = models.ForeignKey(NewGroup, on_delete=models.CASCADE)
    due_date=models.DateField()
    
    
class GroupNote(models.Model):
    g_title=models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    favorite=models.BooleanField(default=False)
    newgroup = models.ForeignKey(NewGroup, on_delete=models.CASCADE)
    
    def __str__(self):
        return self.g_title
    
    
class Todo(models.Model):
    title=models.CharField(max_length=100)
    description=models.TextField()
    created_time=models.DateTimeField(auto_now_add=True)
    reminded_date=models.DateTimeField()
    status=models.BooleanField(default=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    # reminded_time=models.TimeField()
    
 

    
    
