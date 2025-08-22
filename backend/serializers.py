from rest_framework import serializers
from django.conf import settings
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from PyPDF2 import PdfReader, PdfWriter
import os
from .models import User, Document, SignedDocument, DocumentAssignment
from .utils import encrypt_data, decrypt_data, encrypt_bytes

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'role', 'phone', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['first_name'] = encrypt_data(validated_data['first_name'])
        validated_data['last_name'] = encrypt_data(validated_data['last_name'])
        validated_data['email'] = encrypt_data(validated_data['email'])
        validated_data['phone'] = encrypt_data(validated_data['phone'])
        validated_data['password'] = encrypt_data(validated_data['password'])  # ✅ AES encrypt
        return super().create(validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        encrypted_email = encrypt_data(data['email'])
        encrypted_password = encrypt_data(data['password'])

        try:
            user = User.objects.get(email=encrypted_email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        if user.password != encrypted_password:
            raise serializers.ValidationError("Invalid email or password")

        # ✅ Return both original fields + user object or role
        data['user'] = user  # optionally include user
        return data





class DocumentUploadSerializer(serializers.ModelSerializer):
    file = serializers.FileField(write_only=True)

    class Meta:
        model = Document
        fields = ['title', 'uploaded_by', 'file']

    def create(self, validated_data):
        file = validated_data.pop('file')

        # Encrypt title
        encrypted_title = encrypt_data(validated_data['title'])

        # Save the file to disk first to get the actual path
        temp_doc = Document(
            title=encrypted_title,
            uploaded_by=validated_data['uploaded_by']
        )
        temp_doc.file_path.save(file.name, file, save=False)

        # Encrypt the file path (after saving to media/)
        real_file_path = temp_doc.file_path.name  # example: 'documents/sample.pdf'
        encrypted_file_path = encrypt_data(real_file_path)
        temp_doc.file_path.name = encrypted_file_path

        temp_doc.save()  # Final save

        return temp_doc


class DocumentDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ['id', 'title', 'uploaded_by', 'status', 'created_at']



class SignDocumentSerializer(serializers.ModelSerializer):
    signature_image = serializers.ImageField(write_only=True)
    position_x = serializers.FloatField(write_only=True)
    position_y = serializers.FloatField(write_only=True)

    class Meta:
        model = SignedDocument
        fields = ['document', 'signed_by', 'signature_image', 'position_x', 'position_y']

    def create(self, validated_data):
        document = validated_data['document']
        signed_by = validated_data['signed_by']
        signature_image = validated_data['signature_image']
        position_x = validated_data['position_x']
        position_y = validated_data['position_y']

        # ✅ Decrypt the original uploaded file path
        encrypted_path = document.file_path.name
        decrypted_relative_path = decrypt_data(encrypted_path)
        full_pdf_path = os.path.join(settings.MEDIA_ROOT, decrypted_relative_path)

        if not os.path.exists(full_pdf_path):
            raise FileNotFoundError(f"Decrypted file path does not exist: {full_pdf_path}")

        # ✅ Read original PDF
        reader = PdfReader(full_pdf_path)
        writer = PdfWriter()

        # ✅ Prepare signature overlay
        sig_img_bytes = signature_image.read()
        sig_img_io = BytesIO(sig_img_bytes)

        overlay_pdf_io = BytesIO()
        c = canvas.Canvas(overlay_pdf_io, pagesize=letter)
        img_reader = ImageReader(sig_img_io)

        c.drawImage(img_reader, position_x, position_y, width=200, height=50)
        c.save()
        overlay_pdf_io.seek(0)

        overlay_pdf = PdfReader(overlay_pdf_io)
        overlay_page = overlay_pdf.pages[0]

        # ✅ Merge signature onto the first page
        for i, page in enumerate(reader.pages):
            if i == 0:
                page.merge_page(overlay_page)
            writer.add_page(page)

        # ✅ Save signed PDF to file system
        signed_output = BytesIO()
        writer.write(signed_output)
        signed_output.seek(0)

        signed_filename = f"signed_doc_{document.id}_{signed_by.id}.pdf"
        signed_relative_path = os.path.join('signed_documents', signed_filename)
        full_signed_path = os.path.join(settings.MEDIA_ROOT, signed_relative_path)

        os.makedirs(os.path.dirname(full_signed_path), exist_ok=True)

        with open(full_signed_path, 'wb') as f:
            f.write(signed_output.read())

        # ✅ Encrypt the signed file path before saving to DB
        encrypted_signed_path = encrypt_data(signed_relative_path)

        # ✅ Save record to DB
        signed_doc = SignedDocument.objects.create(
            document=document,
            signed_by=signed_by,
            signed_file=encrypted_signed_path,  # now encrypted!
            position_x=position_x,
            position_y=position_y
        )

        return signed_doc


class DocumentAssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentAssignment
        fields = '__all__'

    def create(self, validated_data):
        placed_image = validated_data.get('placed_image', None)

        # Save assignment first to get the file path
        assignment = DocumentAssignment.objects.create(**validated_data)

        if placed_image:
            # Save real full file path temporarily for use in view
            assignment._real_file_path = assignment.placed_image.path

            # Encrypt the path before saving to DB
            real_path = assignment.placed_image.name
            encrypted_path = encrypt_data(real_path)
            assignment.placed_image.name = encrypted_path
            assignment.save()

        return assignment
    


from .models import AuditLog
class AuditLogSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source='document.title', read_only=True)
    user_email = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ['id', 'document', 'document_title', 'performed_by', 'user_email', 'action', 'performed_at']

    def get_user_email(self, obj):
        try:
            return obj.performed_by.email if obj.performed_by else None
        except:
            return None