# book-search-engine

## Screenshot:
![](src/screenshot.png)

## USAGE:
- With Google Book Search, user can search book and save/remove it for later use.

## DESCRIPTION:
- First when user visits the page, he/she can search a book which will then return a list of books available in google.
- Then user will be given option to save the book or if book is already saved the button text will change to 'Book already saved'
- Then when user saves the books they can visit 'See your Books' tab to get the list of saved books.
- From here user can delete the book from the list.

## TECHNICAL DESCRIPTION:
- Apollo Server is implemented that uses GraphQL queries and mutations to fetch and modify data, replacing the existing RESTful API.
- Apollo Server is applied it to the Express.js server as middleware.
- Authentication tackled by the context of a GraphQL API.
- Apollo Provider implemented to communicate with the Apollo Server.

## Site:
- Link to the site: https://ryan7998-book-search-engine.herokuapp.com/