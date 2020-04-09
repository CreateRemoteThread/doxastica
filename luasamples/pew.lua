words = {}

for i,v in ipairs(words) do
	print(v)
end

a = { "pie_flavor1","pie_flavor2","pie_flavor3"}
b = { 80, 443 }
for i,v in ipairs(a) do
        for i2,v2 in ipairs(b) do
                print(v)
                if (v == "pie_flavor1") then
                        print("hello")
                end
                print(v2)
        end
end