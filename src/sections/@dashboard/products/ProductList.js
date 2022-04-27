import PropTypes from 'prop-types';
// material
import { Grid } from '@mui/material';
// import { styled } from '@mui/material/styles';
// import ShopProductCard from './ProductCard';

// ----------------------------------------------------------------------

ProductList.propTypes = {
  products: PropTypes.array.isRequired
};

// const ProductImgStyle = styled('img')({
//   top: 0,
//   width: '100%',
//   height: '100%',
//   objectFit: 'cover',
//   position: 'absolute'
// });

export default function ProductList({ ...other }) {
  return (
    <>
      <Grid container spacing={3} {...other} sx={{ mb: 3 }}>
        <Grid item xs={3} sm={3} md={3} sx={{ display: { xs: 'none', sm: 'block' } }}>
          {/* <img alt="h" src="/static/plan/house.jpg" /> */}
        </Grid>
        <Grid item xs={12} sm={6} md={6}>
          <img alt="h" src="/static/plan/house.jpg" />
        </Grid>
        <Grid item xs={3} sm={3} md={3} sx={{ display: { xs: 'none', sm: 'block' } }}>
          {/* <img alt="h" src="/static/plan/house.jpg" /> */}
        </Grid>
      </Grid>
      <Grid container spacing={3} {...other}>
        <Grid item xs={12} sm={4} md={4}>
          <img alt="h" src="/static/plan/bedroom.jpg" />
        </Grid>
        <Grid item xs={12} sm={4} md={4}>
          <img alt="h" src="/static/plan/kitchen.jpg" />
        </Grid>
        <Grid item xs={12} sm={4} md={4}>
          <img alt="h" src="/static/plan/livingroom.png" />
        </Grid>
      </Grid>
    </>
  );
}
