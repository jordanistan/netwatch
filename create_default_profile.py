from PIL import Image, ImageDraw, ImageFont
import variables

# Create a new image with a white background
size = (200, 200)
img = Image.new('RGB', size, 'white')
draw = ImageDraw.Draw(img)

# Draw a blue circle
circle_center = (100, 100)
circle_radius = 80
draw.ellipse(
    [
        (circle_center[0] - circle_radius, circle_center[1] - circle_radius),
        (circle_center[0] + circle_radius, circle_center[1] + circle_radius)
    ],
    fill='lightblue'
)

# Draw the text "NW" in the center
text = "NW"
draw.text(
    (100, 100),
    text,
    fill='navy',
    anchor="mm",  # Center the text
    font=ImageFont.load_default()
)

# Save the image
img.save(variables.DEFAULT_PROFILE)
