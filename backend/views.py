from datetime import timedelta
import os
import random

from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    User,
    Document,
    SignedDocument,
    DocumentAssignment,
    AuditLog,
    OTPVerification,
)

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    DocumentUploadSerializer,
    DocumentDetailSerializer,
    SignDocumentSerializer,
    DocumentAssignmentSerializer,
    AuditLogSerializer,
)

from .utils import (
    decrypt_data,
    decrypt_bytes,
    fix_base64_padding,
)



class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Return serialized data (decrypt first if needed)
            return Response({
                "message": "User registered successfully",
                "user": {
                    "id": user.id,
                    "first_name": decrypt_data(user.first_name),
                    "last_name": decrypt_data(user.last_name),
                    "email": decrypt_data(user.email),
                    "phone": decrypt_data(user.phone),
                    "role": user.role
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    

from django.contrib.auth import authenticate
class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            role = user.role

            return Response({
                "message": "Login successful",
                "role": role,
                "user": {
                    "id": user.id,
                    "email": decrypt_data(user.email),  # ✅ decrypt before sending
                    "name": f"{decrypt_data(user.first_name)} {decrypt_data(user.last_name)}"
                }
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendDocumentView(APIView):
    def post(self, request):
        serializer = DocumentUploadSerializer(data=request.data)

        if serializer.is_valid():
            doc = serializer.save()
            return Response({
                "message": "Document encrypted and uploaded successfully.",
                "document": {
                    "id": doc.id,
                    "title": request.data.get("title"),  # original title (not encrypted)
                    "uploaded_by": doc.uploaded_by.id,
                    "file_path": doc.file_path.name  # still encrypted
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetEncryptedDocumentView(APIView):
    def get(self, request, document_id):
        try:
            document = Document.objects.get(id=document_id)

            # Decrypt title and file path
            try:
                title = decrypt_data(document.title)
            except Exception:
                title = "[Decryption Error]"

            try:
                decrypted_path = decrypt_data(document.file_path.name)
                file_url = f"{settings.BASE_URL}/media/{decrypted_path}"
            except Exception:
                decrypted_path = "[Decryption Error]"
                file_url = "[Invalid URL]"

            return Response({
                "id": document.id,
                "title_encrypted": document.title,
                "title_decrypted": title,
                "file_path_encrypted": document.file_path.name,
                "file_path_decrypted": decrypted_path,
                "file_url": file_url,
                "status": document.status,
                "uploaded_by": document.uploaded_by_id,
                "created_at": document.created_at,
            }, status=status.HTTP_200_OK)

        except Document.DoesNotExist:
            return Response({"error": "Document not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
           


class AllDecryptedDocumentsView(APIView):
    def get(self, request):
        documents = Document.objects.all()
        response = []

        for doc in documents:
            try:
                title = decrypt_data(doc.title)
            except Exception:
                title = "[Decryption Error]"

            try:
                # ✅ DECRYPT file_path correctly here
                encrypted_path = doc.file_path.name
                decrypted_path = decrypt_data(encrypted_path)
                file_url = f"{settings.BASE_URL}{settings.MEDIA_URL}{decrypted_path}"
            except Exception as e:
                print(f"Decryption failed for file path: {e}")
                decrypted_path = "[Invalid]"
                file_url = "[Invalid URL]"

            response.append({
                "id": doc.id,
                "title": title,
                "file_path": decrypted_path,  # ✅ now correct
                "file_url": file_url,         # ✅ now correct
                "status": doc.status,
                "uploaded_by": doc.uploaded_by_id,
                "created_at": doc.created_at,
            })

        return Response(response)

class GetSignedDocumentView(APIView):
    def get(self, request, pk):
        try:
            signed_doc = SignedDocument.objects.get(pk=pk)

            # Ensure signed_file contains the encrypted file path as string
            encrypted_path = str(signed_doc.signed_file)

            # Fix base64 padding and decrypt
            decrypted_path = decrypt_data(fix_base64_padding(encrypted_path))

            # Build the full file URL
            file_url = f"{settings.BASE_URL}/media/{decrypted_path}"

            return Response({
                "id": signed_doc.id,
                "document_id": signed_doc.document.id,
                "signed_by": signed_doc.signed_by.id,
                "signed_file": decrypted_path,
                "file_url": file_url,
                "position_x": signed_doc.position_x,
                "position_y": signed_doc.position_y,
            }, status=status.HTTP_200_OK)

        except SignedDocument.DoesNotExist:
            return Response({"error": "Signed document not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DocumentAssignmentView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        serializer = DocumentAssignmentSerializer(data=request.data)
        if serializer.is_valid():
            assignment = serializer.save()

            try:
                # Decrypt email of assigned user
                encrypted_email = assignment.assigned_to.email
                assigned_email = decrypt_data(encrypted_email)

                # ✅ Get real (unencrypted) file path
                real_file_path = getattr(assignment, "_real_file_path", None)

                if real_file_path:
                    # Compose and send email with file attached
                    email = EmailMessage(
                        subject="📄 Document Assigned for Signature",
                        body=f"""
Dear {decrypt_data(assignment.assigned_to.first_name)},

You have been assigned a document to sign.
Please open and complete your signature: http://localhost:8000/signing/document/opened/{assignment.document.id}/

Regards,
FACT.Sign
                        """,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[assigned_email],
                    )
                    email.attach_file(real_file_path)
                    email.send()

                    # ✅ Log to AuditLog
                    AuditLog.objects.create(
                        document=assignment.document,
                        performed_by=assignment.assigned_by,
                        action='sent'
                    )

                    # ✅ Success response
                    return Response({
                        "message": "✅ Document assigned and email sent.",
                        "assignment": {
                            "id": assignment.id,
                            "document_id": assignment.document.id,
                            "document_title": decrypt_data(assignment.document.title),
                            "assigned_by": {
                                "id": assignment.assigned_by.id,
                                "name": f"{decrypt_data(assignment.assigned_by.first_name)} {decrypt_data(assignment.assigned_by.last_name)}",
                                "email": decrypt_data(assignment.assigned_by.email)
                            },
                            "assigned_to": {
                                "id": assignment.assigned_to.id,
                                "name": f"{decrypt_data(assignment.assigned_to.first_name)} {decrypt_data(assignment.assigned_to.last_name)}",
                                "email": decrypt_data(assignment.assigned_to.email)
                            },
                            "placed_image": request.build_absolute_uri(f"/media/{assignment.placed_image.name}"),
                            "position_x": assignment.position_x,
                            "position_y": assignment.position_y,
                            "assigned_at": assignment.assigned_at
                        }
                    }, status=status.HTTP_201_CREATED)

                else:
                    return Response({"error": "No valid file in placed_image."}, status=400)

            except Exception as e:
                return Response({"error": "❌ Failed to send email.", "details": str(e)}, status=500)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        assignments = DocumentAssignment.objects.all()
        serializer = DocumentAssignmentSerializer(assignments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


def generate_otp():
    return str(random.randint(100000, 999999))

class SendOTPView(APIView):
    def post(self, request):
        user_id = request.data.get("user_id")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        # 🔐 Decrypt fields
        try:
            email = decrypt_data(fix_base64_padding(user.email))
            first_name = decrypt_data(fix_base64_padding(user.first_name))
            last_name = decrypt_data(fix_base64_padding(user.last_name))
        except Exception as e:
            return Response({"error": "Failed to decrypt user data.", "details": str(e)}, status=500)

        otp_code = generate_otp()
        expiry = timezone.now() + timedelta(minutes=5)

        OTPVerification.objects.create(
            user=user,
            otp_code=otp_code,
            expires_at=expiry
        )

        subject = "Your OTP Code"
        message = f"Hello {first_name},\n\nYour OTP code is: {otp_code}. It will expire in 5 minutes."

        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False  # Make sure to raise error if any
            )
        except Exception as e:
            return Response({"error": "Email sending failed", "details": str(e)}, status=500)

        return Response({
            "message": f"OTP sent to {email}.",
            "otp": otp_code,  # for testing; remove in production
            "user": {
                "id": user.id,
                "first_name": first_name,
                "last_name": last_name,
                "email": email
            }
        }, status=status.HTTP_200_OK)


class VerifyOTPView(APIView):
    def post(self, request):
        user_id = request.data.get("user_id")
        otp = request.data.get("otp")

        if not user_id or not otp:
            return Response({"error": "User ID and OTP are required."}, status=400)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        # 🔍 Find a matching and valid OTP
        otp_entry = OTPVerification.objects.filter(
            user=user,
            otp_code=otp,
            is_used=False,
            expires_at__gt=timezone.now()
        ).first()

        if not otp_entry:
            return Response({"error": "Invalid or expired OTP."}, status=400)

        # ✅ Mark as used
        otp_entry.is_used = True
        otp_entry.save()

        # 🔓 Decrypt user info for response
        try:
            email = decrypt_data(fix_base64_padding(user.email))
            first_name = decrypt_data(fix_base64_padding(user.first_name))
            last_name = decrypt_data(fix_base64_padding(user.last_name))
        except Exception as e:
            return Response({"message": "OTP verified but failed to decrypt user info", "details": str(e)}, status=500)

        return Response({
            "message": "✅ OTP verified successfully.",
            "user": {
                "id": user.id,
                "first_name": first_name,
                "last_name": last_name,
                "email": email
            }
        }, status=200)

    

class DocumentOpenedView(APIView):
    # permission_classes = [IsAuthenticated]  # Open for email-based access

    def get(self, request, document_id):
        try:
            document = Document.objects.get(id=document_id)
            user_id = request.GET.get('user_id')

            if not user_id:
                return Response({"error": "Missing user_id in URL"}, status=400)

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=404)

            # Update audit log
            audit_entry = AuditLog.objects.filter(document=document, performed_by=user).order_by('-performed_at').first()
            if audit_entry:
                audit_entry.action = 'opened'
                audit_entry.save()
            else:
                AuditLog.objects.create(document=document, action='opened', performed_by=user)

            return Response({
                "message": "✅ Document status updated to opened.",
                "document": {
                    "id": document.id,
                    "title_encrypted": document.title,
                    "title_decrypted": decrypt_data(document.title),
                    "file_path_encrypted": document.file_path.name,
                    "file_path_decrypted": decrypt_data(document.file_path.name),
                    "file_url": request.build_absolute_uri(f"/media/{decrypt_data(document.file_path.name)}"),
                },
                "opened_by": {
                    "id": user.id,
                    "name": f"{decrypt_data(user.first_name)} {decrypt_data(user.last_name)}",
                    "email": decrypt_data(user.email)
                },
                "opened_at": audit_entry.performed_at if audit_entry else "now"
            }, status=200)

        except Document.DoesNotExist:
            return Response({"error": "Document not found."}, status=404)

class SignedDocumentView(APIView):
    def post(self, request, document_id):
        try:
            document = Document.objects.get(id=document_id)
        except Document.DoesNotExist:
            return Response({"error": "Document not found."}, status=404)

        mutable_data = request.data.copy()
        mutable_data['document'] = document_id

        serializer = SignDocumentSerializer(data=mutable_data)
        if serializer.is_valid():
            signed_doc = serializer.save()

            # ✅ Update audit log
            signed_by = signed_doc.signed_by
            latest_entry = AuditLog.objects.filter(
                document=document,
                performed_by=signed_by
            ).order_by('-performed_at').first()

            if latest_entry:
                latest_entry.action = 'signed'
                latest_entry.save()
            else:
                AuditLog.objects.create(
                    document=document,
                    performed_by=signed_by,
                    action='signed'
                )

            return Response({
                "message": "✅ Document signed successfully.",
                "signed_document": {
                    "id": signed_doc.id,
                    "document_id": signed_doc.document.id,
                    "signed_by": {
                        "id": signed_doc.signed_by.id,
                        "name": f"{decrypt_data(signed_doc.signed_by.first_name)} {decrypt_data(signed_doc.signed_by.last_name)}",
                        "email": decrypt_data(signed_doc.signed_by.email)
                    },
                    "signed_file_decrypted": decrypt_data(signed_doc.signed_file.name),
                    "signed_file_url": request.build_absolute_uri(f"/media/{decrypt_data(signed_doc.signed_file.name)}"),
                    "position_x": signed_doc.position_x,
                    "position_y": signed_doc.position_y,
                }
            }, status=201)

        return Response(serializer.errors, status=400)


class AuditLogListView(APIView):
    def get(self, request, document_id):
        logs = AuditLog.objects.filter(document_id=document_id).order_by('performed_at')
        serializer = AuditLogSerializer(logs, many=True)
        return Response(serializer.data, status=200)
    

