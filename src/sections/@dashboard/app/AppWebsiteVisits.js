import { merge } from 'lodash';
import ReactApexChart from 'react-apexcharts';
// material
import { Card, CardHeader, Box } from '@mui/material';
//
import { BaseOptionChart } from '../../../components/charts';

// ----------------------------------------------------------------------

const CHART_DATA = [
  {
    name: 'Micro-onde',
    // type: 'column',
    type: 'line',
    data: [23, 11, 22, 27, 13, 22, 37, 21, 44, 22, 30]
  },
  {
    name: 'Refrigerateur',
    type: 'bar',
    data: [44, 55, 91, 67, 22, 43, 21, 41, 56, 97, 43]
  },
  {
    name: 'Climatiseur',
    type: 'line',
    data: [30, 25, 36, 30, 45, 35, 64, 52, 59, 36, 39]
  },
  {
    name: 'Lave linge',
    type: 'line',
    data: [39, 45, 56, 30, 45, 35, 34, 52, 59, 36, 59]
  }
];

export default function AppWebsiteVisits() {
  const chartOptions = merge(BaseOptionChart(), {
    stroke: { width: [2, 2, 2, 2, 2] },
    plotOptions: { bar: { columnWidth: '11%', borderRadius: 4 } },
    fill: { type: ['solid', 'gradient', 'solid'] },
    labels: ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'],
    xaxis: { type: 'number' },
    tooltip: {
      shared: true,
      intersect: false,
      y: {
        formatter: (y) => {
          if (typeof y !== 'undefined') {
            return `${y.toFixed(0)} kW`;
          }
          return y;
        }
      }
    }
  });

  return (
    <Card>
      <CardHeader title="Mesure wattage" subheader="en fonction du temps(s)" />
      <Box sx={{ p: 3, pb: 1 }} dir="ltr">
        <ReactApexChart type="line" series={CHART_DATA} options={chartOptions} height={364} />
      </Box>
    </Card>
  );
}
