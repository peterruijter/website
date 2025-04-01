fetch('https://cors-anywhere.herokuapp.com/https://feeds.nos.nl/nosnieuwsalgemeen')
  .then(response => response.text())
  .then(xml => {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xml, 'text/xml');

    const articles = xmlDoc.querySelectorAll('item');

    const articleContainer = document.getElementById('article-container');

    articles.forEach(article => {
      const articleElement = document.createElement('div');
      articleElement.classList.add('article');

      const photoElement = document.createElement('img');
      photoElement.src = article.querySelector('enclosure').getAttribute('url');
      photoElement.alt = article.querySelector('title').textContent;

      const headlineElement = document.createElement('h2');
      headlineElement.textContent = article.querySelector('title').textContent;

      const descriptionElement = document.createElement('p');
      descriptionElement.textContent = article.querySelector('description').textContent;

      const column1 = document.createElement('div');
      column1.classList.add('column');
      column1.appendChild(photoElement);

      const column2 = document.createElement('div');
      column2.classList.add('column');
      column2.appendChild(headlineElement);
      column2.appendChild(descriptionElement);

      articleElement.appendChild(column1);
      articleElement.appendChild(column2);

      articleContainer.appendChild(articleElement);
    });
  })
  .catch(error => console.error(error));
