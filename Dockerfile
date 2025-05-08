##############################
# Install node image to docker
FROM node:22-alpine

# Set the working directory
WORKDIR /usr/src/app

###########################
# Copy the code over docker

# Copy the .env file
COPY .env.docker ./

# Copy the package.json file
COPY package.json package-lock.json ./

# Install the node packages
RUN npm ci

# Copy the source
COPY . .

##################
# Build the source
RUN npm run build:nest

#########################
# Expose the port and run
EXPOSE 3000
CMD [ "npm", "start" ]
