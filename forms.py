from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_wtf import FlaskForm

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=200)])
