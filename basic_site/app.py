from flask import Flask, render_template, request, redirect
import requests
import json


app = Flask(__name__)

# home page; prompts user to search for a recipe ingredient
@app.route('/')
def home():
    return render_template('home.html')    

# when the user submits the above form, the data they input is sent here
@app.route('/verify', methods = ['POST', 'GET'])
def verify():
    if request.method == 'POST':
        ingredient = request.form['ingredient']
        return redirect(f"/recipesSearch/")   

# searches for recipes containing ingredient submitted by user
@app.route("/recipesSearch/")
def recipesSearch(ingredient):
    
    search_item = ingredient
    app_id = "4b0d43a5"
    app_key = "83064f92ec75608c4ce456d960515aeb"
    max_num_ingredients = "5"
    
    url = "https://api.edamam.com/api/recipes/v2?type=public&q=" + search_item +"&app_id=" + app_id +"&app_key=" + app_key + "&ingr=" + max_num_ingredients
    response = requests.request("GET", url)
    dictionary = json.loads(response.text)
    #recipies = dictionary["hits"][0]["recipe"]["label"]
    #image = dictionary["hits"][0]["recipe"]["image"]
    

    view = ""
    ingr = "Ingredients:<br>"
    price = ""
    #print(len(dictionary["hits"]))
    for x in dictionary["hits"]:
        recipies = x["recipe"]["label"]
        image = x["recipe"]["image"]
        for y in x["recipe"]["ingredients"]:
            url3 = "https://api.kroger.com/v1/products?filter.term=" + y["food"]
            
            ingr += "- " + y["text"] + " " + "<br>"
        
        view += "<body> <p>" + recipies + "</p><body> <p>" + ingr + "</p><img src="+ image +" alt='not found'></body> "
    #print(recipies)
    

    
    #view = "<body> <p>" + recipies + "</p>  <img src="+ image +" alt='not found'> </body> "
    return view

