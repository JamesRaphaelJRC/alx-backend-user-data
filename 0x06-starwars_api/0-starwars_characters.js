#!/usr/bin/node
const argv = process.argv;
const filmURL = 'https://swapi-api.hbtn.io/api/films/';
const movieURL = `${filmURL}${argv[2]}/`;

const request = require('request');

request(movieURL, function (error, response, body) {
  if (error == null) {
    const body = JSON.parse(body);
    const characters = body.characters;

    if (characters && characters.length > 0) {
      const limit = characters.length;
      requestCharacter(0, characters[0], characters, limit);
    }
  } else {
    console.log(error);
  }
});

function requestCharacter (idx, url, characters, limit) {
  if (idx === limit) {
    return;
  }
  request(url, function (error, response, body) {
    if (!error) {
      const rbody = JSON.parse(body);
      console.log(rbody.name);
      idx++;
      requestCharacter(idx, characters[idx], characters, limit);
    } else {
      console.error('error:', error);
    }
  });
}
