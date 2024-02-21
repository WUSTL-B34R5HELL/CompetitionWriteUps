import cv2

#convert image to grayscale
f = cv2.imread("uwu.png")
y = cv2.imread("owo.png")
x = cv2.imread("fiscl.png")

#convert grayscale array to corpu format
print(len(f))
print(len(y))
print(len(f[0]))
new = f
for i in range(len(f)):
    for j in range(len(f[0])):
       new[i][j] = f[i][j] ^ y[i][j] 
        
cv2.imwrite("new.png", new)
